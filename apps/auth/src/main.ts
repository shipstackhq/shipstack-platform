import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { ConsolePrismaService } from './core/database/console-prisma.service';
import { resolveSlugFromHost } from './common/resolve-slug-from-host';
import type { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';

// Phase 1: origin-enforcement middleware moved in wholesale from
// apps/platform-api/src/main.ts:9-64, per the plan's "CORS / origin
// enforcement" section. Unlike platform-api's version, the "non-direct-mode
// bypasses CORS" branch is dropped entirely — FAPI serves browser traffic
// exclusively, so every request is subject to origin enforcement
// unconditionally now. The fail-open-on-empty-allowedOrigins behavior is
// kept as-is (documented gap, not fixed here).
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix('api/v1');
  app.use(cookieParser());

  const console_ = app.get(ConsolePrismaService);
  const originCache = new Map<string, { allowedOrigins: string[]; expiresAt: number }>();
  const ORIGIN_CACHE_TTL_MS = 30_000;

  app.use(async (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    // Resolve the same way the guards do — purely from the Host header
    // (per-project subdomain). FAPI has no legitimate caller that lacks a
    // resolvable per-project hostname, so there is no publishableKey-param
    // fallback here either (see EnvironmentGuard).
    const slug = resolveSlugFromHost(req.headers.host);

    let allowOrigin = true; // default: reflect, matching prior behavior when no slug is present yet
    if (origin && slug) {
      let entry = originCache.get(slug);
      if (!entry || entry.expiresAt < Date.now()) {
        const environment = await console_.environment.findUnique({ where: { slug }, select: { allowedOrigins: true } });
        entry = { allowedOrigins: environment?.allowedOrigins ?? [], expiresAt: Date.now() + ORIGIN_CACHE_TTL_MS };
        originCache.set(slug, entry);
      }
      // Empty allowedOrigins means "not configured yet" — fail open during
      // rollout rather than locking out every existing direct-mode project;
      // tighten to fail-closed once allowedOrigins is a required setup step.
      // (Documented gap, carried over unchanged from platform-api — not
      // silently fixed as part of this migration.)
      allowOrigin = entry.allowedOrigins.length === 0 || entry.allowedOrigins.includes(origin);
    }

    if (origin && allowOrigin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }

    if (req.method === 'OPTIONS') {
      if (origin && !allowOrigin) return res.status(403).end();
      return res.status(204).end();
    }
    if (origin && !allowOrigin) return res.status(403).json({ error: 'Origin not allowed' });

    next();
  });

  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  app.useGlobalFilters(new AllExceptionsFilter());

  // /api/v1-prefixed docs, matching setGlobalPrefix above — SwaggerModule
  // mounts relative to the already-prefixed app, so routes shown in the UI
  // read as the real, callable paths (e.g. /api/v1/auth/client/sign_ins),
  // not the bare controller paths. Mounted unconditionally (not gated behind
  // NODE_ENV) since FAPI has no dashboard/admin surface of its own this could
  // leak sensitive internals into — every route documented here is already
  // a public, Host-header-resolved endpoint a real client is expected to
  // call directly.
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Shipstack FAPI')
    .setDescription(
      'Frontend API for Shipstack Auth — the client-as-root API real browsers, ' +
      'backend-proxy servers, and SDKs call directly. Mirrors the shape of ' +
      "Clerk's own FAPI: Client is the root of trust, sign-ins/sign-ups/sessions " +
      'are sub-resources of /auth/client. See the "Error envelope" schema for ' +
      "the coded error shape every 4xx/5xx below can return.",
    )
    .setVersion('1.0')
    .addCookieAuth('__client', { type: 'apiKey', in: 'cookie' }, 'directModeCookie')
    .addBasicAuth({ type: 'http', scheme: 'basic' }, 'backendProxyBasicAuth')
    .build();
  const swaggerDocument = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/v1/docs', app, swaggerDocument);

  // Distinct from platform-api's default port (9000) so both apps can run
  // simultaneously in local dev during the migration window.
  await app.listen(process.env.PORT ?? 9001);
}
bootstrap();

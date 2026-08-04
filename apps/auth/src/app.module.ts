import 'dotenv/config';
import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { PrismaModule } from './core/database/prisma.module';
import { AuthModule } from './modules/auth/auth.module';
import { EnvironmentModule } from './modules/environment/environment.module';
import { WellKnownModule } from './modules/well-known/well-known.module';

// Phase 1: FAPI-A route modules wired in (auth, config, well-known — the
// already-public routes moved off platform-api). OAuthModule (the legacy
// oauth/google/authorize, oauth/exchange, oauth/google/callback routes) was
// deleted in the Phase 9 cutover (docs/unified-attempt-architecture.md) —
// superseded by AuthModule's own AttemptsController/OAuthCallbackController
// (GoogleOAuthStrategy). Per the
// database-access-boundary rule (migration plan Section 4), this module
// graph must never import admin-shaped modules (IdentitiesManagementModule,
// admin halves of QuotaModule/SubscriptionsModule etc.) even after routes
// keep getting added in Phase 2/3 — FAPI's module graph should be
// structurally incapable of constructing the admin service classes, not just
// choose not to route to them. None of the modules below reference any such
// admin module.
//
// Phase 2: QuotaModule/SubscriptionsModule added — these are FAPI's OWN
// read-only, self-service-only service classes (quota.service.ts /
// subscriptions.service.ts in apps/fapi), NOT imports of platform-api's
// admin-capable QuotaService/SubscriptionsService. No increment/decrement/
// migrate/assign/cancel/change-plan exists anywhere in FAPI's module graph.
@Module({
  imports: [
    NestConfigModule.forRoot({ isGlobal: true }),
    PrismaModule,
    AuthModule,
    EnvironmentModule,
    WellKnownModule,
  ],
})
export class AppModule {}

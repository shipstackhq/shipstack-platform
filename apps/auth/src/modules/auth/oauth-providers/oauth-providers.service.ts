import { enqueueOutboxEvent } from "@/core/outbox/outbox";
import { Injectable, NotFoundException } from '@nestjs/common';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { EncryptionService } from '@/core/encryption/encryption.service';
import { OAuthProvider } from '@/generated/console/client';
import type { OAuthProvider as PlatformOAuthProvider } from '@/generated/platform/enums';
import { generateId } from '@/common/utils/id';

// Duplicated verbatim from
// apps/platform-api/src/modules/oauth-providers/oauth-providers.service.ts
// per the migration plan's "duplicate now, don't extract" decision.
@Injectable()
export class OAuthProvidersService {
  constructor(
    private console: ConsolePrismaService,
    private platform: PlatformPrismaService,
    private encryption: EncryptionService,
  ) {}

  // Made public here (originally private on the legacy oauth.service.ts,
  // deleted in the Phase 9 cutover) so Phase 3's SignInStrategy
  // implementations (modules/auth/attempts/strategies/) could share one
  // identity-resolution path without a circular module dependency at the
  // time — OAuthModule imported AuthModule (for AuthService), so
  // AuthModule's own strategies couldn't import OAuthModule back.
  // OAuthProvidersModule has no such dependency, making it the natural
  // shared home; this is now the ONLY caller, OAuthModule no longer exists.
  // provider is the full OAuthProvider enum (not a 'GOOGLE' literal) so
  // GitHub needs no change here — see google-oauth.strategy.ts /
  // (a new strategy class, plus a case in the default-credentials switch).
  async findOrCreateOAuthIdentity(
    environmentId: string,
    providerUserId: string,
    email: string,
    firstName: string | null,
    lastName: string | null,
    avatar: string | null,
    provider: PlatformOAuthProvider,
  ) {
    const normalizedEmail = email.toLowerCase().trim();

    const existingProvider = await this.platform.identityProvider.findUnique({
      where: { provider_providerUserId: { provider, providerUserId } },
      include: { identity: true },
    });

    if (existingProvider) {
      const identity = await this.platform.identity.update({
        where: { id: existingProvider.identity.id },
        data: { email: normalizedEmail, firstName, lastName, avatar },
      });
      return { identity, isNew: false };
    }

    const existingIdentity = await this.platform.identity.findUnique({
      where: { environmentId_email: { environmentId, email: normalizedEmail } },
    });

    if (existingIdentity) {
      const [identity] = await Promise.all([
        this.platform.identity.update({
          where: { id: existingIdentity.id },
          data: { firstName, lastName, avatar },
        }),
        this.platform.identityProvider.create({
          data: { id: generateId(), identityId: existingIdentity.id, provider, providerUserId },
        }),
      ]);
      return { identity, isNew: false };
    }

    const identity = await this.platform.identity.create({
      data: {
        id: generateId(),
        environmentId,
        email: normalizedEmail,
        firstName,
        lastName,
        avatar,
        providers: {
          create: { id: generateId(), provider, providerUserId },
        },
      },
    });

    // Billing assigns plans; Auth only announces the new identity (D14).
    await enqueueOutboxEvent(this.platform, {
      aggregateType: "identity",
      aggregateId: identity.id,
      eventType: "identity.created",
      payload: { identityId: identity.id, environmentId },
    });

    return { identity, isNew: true };
  }

  async getDecrypted(environmentId: string, provider: OAuthProvider) {
    const config = await this.console.oAuthProviderConfig.findUnique({
      where: { environmentId_provider: { environmentId, provider } },
    });

    if (!config) return this.getShipstackDefaults(provider);

    if (!config.useCustomCredentials) {
      return this.getShipstackDefaults(provider);
    }

    if (!config.providerClientId || !config.providerClientSecret) {
      throw new NotFoundException('Custom credentials not configured');
    }

    return {
      id: config.id,
      provider: config.provider,
      providerClientId: this.encryption.decrypt(config.providerClientId),
      providerClientSecret: this.encryption.decrypt(config.providerClientSecret),
    };
  }

  private getShipstackDefaults(provider: OAuthProvider) {
    if (provider === 'GOOGLE') {
      const clientId = process.env.DEFAULT_GOOGLE_CLIENT_ID;
      const clientSecret = process.env.DEFAULT_GOOGLE_CLIENT_SECRET;
      if (!clientId || !clientSecret) {
        throw new NotFoundException('Shipstack default Google credentials not configured');
      }
      return {
        id: 'shipstack-default',
        provider: OAuthProvider.GOOGLE,
        successUrl: null,
        providerClientId: clientId,
        providerClientSecret: clientSecret,
      };
    }
    throw new NotFoundException(`No default credentials for provider: ${provider}`);
  }
}

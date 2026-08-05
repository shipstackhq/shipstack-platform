import { Injectable, Logger } from '@nestjs/common';
import { PlatformPrismaService } from '@/core/database/platform-prisma.service';
import { OAuthProvidersService } from '@/modules/auth/oauth-providers/oauth-providers.service';
import { OAuthProvider } from '@/generated/platform/enums';
import { OAuthStrategyBase, type OAuthProfile } from './oauth-strategy.base';

// Real implementation, now a thin adapter over OAuthStrategyBase (Phase 8 —
// docs/unified-attempt-architecture.md). Only Google's own endpoint URLs,
// scope, extra authorize params, and profile field mapping live here; PKCE/
// state/attempt-lookup/identity-resolution all live in the shared base.
@Injectable()
export class GoogleOAuthStrategy extends OAuthStrategyBase {
  protected readonly logger = new Logger(GoogleOAuthStrategy.name);
  protected readonly provider = OAuthProvider.GOOGLE;
  protected readonly authorizeUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  protected readonly tokenUrl = 'https://oauth2.googleapis.com/token';
  protected readonly userinfoUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
  protected readonly scope = 'openid email profile';

  constructor(platform: PlatformPrismaService, oauthProviders: OAuthProvidersService) {
    super(platform, oauthProviders);
  }

  protected extraAuthorizeParams(): Record<string, string> {
    return { access_type: 'offline' };
  }

  protected mapProfile(data: any): OAuthProfile {
    return {
      providerUserId: data.sub,
      // Google reliably returns email with the `email` scope requested, but
      // OAuthProfile.email is nullable (see its own doc comment) — guard
      // here too for type honesty and defense in depth, same as Microsoft.
      email: data.email ?? null,
      firstName: data.given_name ?? null,
      lastName: data.family_name ?? null,
      avatar: data.picture ?? null,
    };
  }
}

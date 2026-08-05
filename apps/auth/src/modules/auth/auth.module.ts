import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { SessionsController } from './sessions.controller';
import { PrismaModule } from '@/core/database/prisma.module';
import { IdentityTokenModule } from '@/core/identity-token/identity-token.module';
import { MailModule } from '@/core/mail/mail.module';
import { OAuthProvidersModule } from '@/modules/auth/oauth-providers/oauth-providers.module';
import { EnvironmentModule } from '@/modules/environment/environment.module';
import { ClientResolverService } from '@/common/client-resolver.service';
import { SessionGuard } from '@/common/guards/session.guard';
import { AttemptsController, OAuthCallbackController } from './attempts/attempts.controller';
import { AttemptsService } from './attempts/attempts.service';
import { StrategyRegistryService } from './attempts/strategy-registry.service';
import { GoogleOAuthStrategy } from './attempts/strategies/google-oauth.strategy';
import { EmailCodeStrategy } from './attempts/strategies/email-code.strategy';
import { EmailPasswordStrategy } from './attempts/strategies/email-password.strategy';
import { SignUpAttemptsController } from './attempts/sign-up-attempts.controller';
import { SignUpAttemptsService } from './attempts/sign-up-attempts.service';
import { SignUpStrategyRegistryService } from './attempts/sign-up-strategy-registry.service';
import { EmailPasswordSignUpStrategy } from './attempts/strategies/email-password-signup.strategy';

// Phase 2: ClientResolverService/SessionGuard added as providers — the new
// `auth/me` PATCH route (Tier B) is the first Tier B consumer in this
// module. See quota.module.ts / subscriptions.module.ts for the same
// pattern (no dedicated ClientResolverModule exists yet).
//
// AttemptsController/OAuthCallbackController/SignUpAttemptsController and
// their services/strategy registries are the unified sign-in/sign-up
// attempt architecture (docs/unified-attempt-architecture.md) — as of the
// Phase 9 cutover, this IS the only sign-in/sign-up/OAuth surface; the old
// register/login/oauth/* routes and OAuthModule were deleted.
// GoogleOAuthStrategy (Phase 8) shares
// OAuthStrategyBase; both EmailPassword strategies are real as of Phases
// 3/4; EmailCodeStrategy is real as of Phase 5. OAuthProvidersModule
// imported directly here (not via a since-deleted OAuthModule) — see
// OAuthProvidersService's own comment on findOrCreateOAuthIdentity for the
// (now historical) circular-dependency reasoning.
@Module({
  imports: [PrismaModule, IdentityTokenModule, MailModule, OAuthProvidersModule, EnvironmentModule],
  controllers: [AuthController, SessionsController, AttemptsController, OAuthCallbackController, SignUpAttemptsController],
  providers: [
    AuthService, ClientResolverService, SessionGuard,
    AttemptsService, StrategyRegistryService, GoogleOAuthStrategy, EmailCodeStrategy, EmailPasswordStrategy,
    SignUpAttemptsService, SignUpStrategyRegistryService, EmailPasswordSignUpStrategy,
  ],
  exports: [AuthService],
})
export class AuthModule {}

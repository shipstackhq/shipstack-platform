import { Injectable } from '@nestjs/common';
import { AuthMethod } from '@/generated/platform/enums';
import type { SignInStrategy } from './sign-in-strategy.interface';
import { GoogleOAuthStrategy } from './strategies/google-oauth.strategy';
import { EmailCodeStrategy } from './strategies/email-code.strategy';
import { EmailPasswordStrategy } from './strategies/email-password.strategy';

// Single dispatch point: AuthMethod -> SignInStrategy implementation. The
// generic route handlers (AttemptsService) never branch on strategy name
// themselves — they resolve the implementation here and call the interface
// uniformly. Each phase (docs/unified-attempt-architecture.md) adds one
// entry here, replacing a stub or adding a new real implementation,
// without the route handlers or this class's own shape needing to change.
@Injectable()
export class StrategyRegistryService {
  constructor(
    private googleOAuth: GoogleOAuthStrategy,
    private emailCode: EmailCodeStrategy,
    private emailPassword: EmailPasswordStrategy,
  ) {}

  resolve(strategy: AuthMethod): SignInStrategy {
    switch (strategy) {
      case AuthMethod.GOOGLE:
        return this.googleOAuth;
      case AuthMethod.EMAIL_CODE:
        return this.emailCode;
      case AuthMethod.EMAIL_PASSWORD:
        return this.emailPassword;
      default:
        throw new Error(`No SignInStrategy registered for "${strategy}" yet — see docs/unified-attempt-architecture.md's phase list.`);
    }
  }
}

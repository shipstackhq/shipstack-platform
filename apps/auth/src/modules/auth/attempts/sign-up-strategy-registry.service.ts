import { Injectable } from '@nestjs/common';
import { AuthMethod } from '@/generated/platform/enums';
import type { SignUpStrategy } from './sign-up-strategy.interface';
import { EmailPasswordSignUpStrategy } from './strategies/email-password-signup.strategy';

// Sign-up's own registry, parallel to StrategyRegistryService — kept
// separate rather than merged since SignUpStrategy is its own interface
// (see sign-up-strategy.interface.ts's own doc comment on why sign-in and
// sign-up aren't unified into one generic Attempt concept).
@Injectable()
export class SignUpStrategyRegistryService {
  constructor(private emailPassword: EmailPasswordSignUpStrategy) {}

  resolve(strategy: AuthMethod): SignUpStrategy {
    switch (strategy) {
      case AuthMethod.EMAIL_PASSWORD:
        return this.emailPassword;
      default:
        throw new Error(`No SignUpStrategy registered for "${strategy}" yet — see docs/unified-attempt-architecture.md's phase list.`);
    }
  }
}

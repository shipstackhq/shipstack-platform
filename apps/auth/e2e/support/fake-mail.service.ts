import { Injectable } from '@nestjs/common';

// Drop-in replacement for src/core/mail/mail.service.ts, swapped in via
// Test.createTestingModule(...).overrideProvider(MailService).useValue(...)
// in support/app.ts. Captures each send's plaintext code/token instead of
// emailing or logging it — this is the only way an e2e test can complete a
// flow like EMAIL_CODE sign-in, since the plaintext code is NEVER
// persisted anywhere (only its SHA-256 hash is stored — see
// EmailCodeStrategy.prepare()); a real test has no other way to learn what
// code to submit back.
//
// Overriding a provider via the DI container (not monkey-patching, not
// intercepting SMTP) is @nestjs/testing's own first-class, @publicApi
// mechanism (TestingModuleBuilder#overrideProvider) — every consumer of
// MailService (EmailCodeStrategy, AuthService's verify-email/password-reset
// paths, etc.) receives this instance automatically, with zero changes to
// any of that code.
@Injectable()
export class FakeMailService {
  verificationEmails: Array<{ to: string; token: string; projectName?: string }> = [];
  verificationCodes: Array<{ to: string; code: string; projectName?: string }> = [];
  passwordResets: Array<{ to: string; token: string; projectName?: string }> = [];

  async sendVerificationEmail(to: string, token: string, projectName?: string) {
    this.verificationEmails.push({ to, token, projectName });
  }

  async sendVerificationCode(to: string, code: string, projectName?: string) {
    this.verificationCodes.push({ to, code, projectName });
  }

  async sendPasswordReset(to: string, token: string, projectName?: string) {
    this.passwordResets.push({ to, token, projectName });
  }

  // Convenience for tests — the code that matters is always the most
  // recent one sent to a given address (a fresh prepare_first_factor call
  // supersedes any earlier one for the same attempt/identity).
  lastCodeFor(to: string): string | undefined {
    return [...this.verificationCodes].reverse().find(c => c.to === to)?.code;
  }

  lastVerificationTokenFor(to: string): string | undefined {
    return [...this.verificationEmails].reverse().find(e => e.to === to)?.token;
  }

  lastPasswordResetTokenFor(to: string): string | undefined {
    return [...this.passwordResets].reverse().find(e => e.to === to)?.token;
  }

  clear() {
    this.verificationEmails = [];
    this.verificationCodes = [];
    this.passwordResets = [];
  }
}

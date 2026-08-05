import type { SignUpAttemptModel } from '@/generated/platform/models/SignUpAttempt';
import type { AttemptOutcome, PreparedFirstFactor } from './sign-in-strategy.interface';

// Sign-up's own strategy interface, distinct from SignInStrategy — kept
// separate (not a shared generic) because sign-up genuinely has different
// inputs (firstName/lastName collection, an "identity created but not yet
// verified" outcome sign-in never has, since you can't sign in to an
// identity that doesn't exist yet). See
// docs/unified-attempt-architecture.md's SignIn/SignUp split rationale
// (mirrors Clerk's own separate /client/sign_ins vs /client/sign_ups
// resources, confirmed via source this session).
export interface SignUpStrategy {
  prepare(attempt: SignUpAttemptModel): Promise<PreparedFirstFactor>;
  attempt(attempt: SignUpAttemptModel, input: unknown): Promise<SignUpOutcome>;
  resolveExternal(request: unknown): Promise<{ attemptId: string; outcome: SignUpOutcome }>;
}

// Extends AttemptOutcome with sign-up's one genuinely distinct case: an
// Identity now exists, but the environment requires email verification
// before any session can be issued — mirrors register()'s existing
// requiresEmailVerification branch (auth.service.ts), which predates this
// interface and is reused, not reimplemented, by EmailPasswordSignUpStrategy.
export type SignUpOutcome =
  | AttemptOutcome
  | { result: 'pending-verification'; identityId: string };

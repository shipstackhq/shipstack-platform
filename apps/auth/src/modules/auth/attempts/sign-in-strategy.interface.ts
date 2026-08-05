import type { SignInAttemptModel } from '@/generated/platform/models/SignInAttempt';

// See docs/unified-attempt-architecture.md for the full design rationale.
// Deliberately validated against TWO structurally different strategies
// (OAuth: redirect-based, resolves via an external party hitting FAPI
// directly; EmailCode: same-device, resolves via the client submitting a
// proof directly) before either gets real logic — see
// GoogleOAuthStrategy/EmailCodeStrategy stubs in this same directory. The
// risk this guards against: an interface shaped by implementing one
// strategy first tends to silently become THAT strategy's shape, and every
// other strategy has to awkwardly bend to fit it later.

export interface PreparedFirstFactor {
  // Non-null only for strategies where resolution happens via a
  // navigation, not a direct client call to attempt() — OAuth, and
  // magic link's cross-device case. EmailCode/Passkey/Password leave this
  // undefined.
  externalRedirectUrl?: string;
  // Opaque, strategy-owned — stored verbatim into
  // SignInAttempt.verificationData. Never interpreted by the generic route
  // handler, only read back by this same strategy's own attempt()/
  // resolveExternal() later.
  verificationData: unknown;
  // How long THIS verification step is valid (OTP/magic-link expiry,
  // OAuth state expiry) — distinct from the whole attempt's own expiresAt.
  verificationExpiresAt: Date;
}

export type AttemptOutcome =
  | { result: 'complete'; identityId: string; isNewIdentity: boolean }
  | { result: 'failed'; reason: string }
  // e.g. a passkey ceremony needing a second round trip, or an OTP retry
  // after a wrong code (verificationAttempts incremented, still pending).
  | { result: 'still-pending' };

export interface SignInStrategy {
  // Called from POST /auth/sign_ins/:id/prepare_first_factor. Does
  // whatever async/external setup the strategy needs (send an OTP/magic-
  // link email, build an OAuth consent URL, generate a WebAuthn
  // challenge).
  prepare(attempt: SignInAttemptModel): Promise<PreparedFirstFactor>;

  // Called from POST /auth/sign_ins/:id/attempt_first_factor, ONLY for
  // strategies where the client submits a direct proof (OTP code, passkey
  // assertion, password). Strategies that resolve via external callback
  // (OAuth; magic-link clicked in a different tab/device) don't implement
  // meaningful behavior here — see resolveExternal() instead. Both methods
  // exist on the interface rather than picking one, because forcing every
  // strategy through the SAME single method is exactly the "shaped by the
  // first implementation" trap this interface is designed to avoid — a
  // strategy is honest about which path it actually uses by which method
  // it does real work in.
  attempt(attempt: SignInAttemptModel, input: unknown): Promise<AttemptOutcome>;

  // Called from a SHARED callback/verify endpoint (/auth/oauth_callback,
  // magic-link's /verify) for strategies resolved by an external party
  // hitting FAPI directly, not the original client. Given the callback
  // request's own data (OAuth's code+state, magic-link's token), find the
  // matching attempt and resolve it. Strategies with no external-callback
  // path (EmailCode, Passkey, Password) don't implement meaningful
  // behavior here.
  resolveExternal(request: unknown): Promise<{ attemptId: string; outcome: AttemptOutcome }>;
}

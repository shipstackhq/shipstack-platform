// Machine-readable error codes FAPI exceptions can carry, mirroring the
// `code` field on Clerk's real FAPI error envelope (see
// docs/error-code-convention-task.md and clerk-javascript-reference's
// AuthErrorReason for the naming precedent this follows: lowercase,
// underscore-separated, prefixed by the subsystem it belongs to).
//
// Scoped to what auth/guard code actually throws today — not a taxonomy
// for products that don't exist yet. Extend this object (and only this
// object) when a new throw site adopts the convention.
export const ErrorCode = {
  // Environment resolution (guards) + secret-bearer credentials
  EnvironmentUnresolved: 'environment_unresolved',
  InvalidCredentials: 'invalid_credentials',

  // Client (device/browser) resolution
  ClientInvalid: 'client_invalid',
  ClientRevoked: 'client_revoked',
  ClientExpired: 'client_expired',
  ClientTokenReuseDetected: 'client_token_reuse_detected',
  ClientCredentialsMissing: 'client_credentials_missing',

  // Dev-browser resolution
  DevBrowserInvalidOrExpired: 'dev_browser_invalid_or_expired',
  DevBrowserUnauthenticated: 'dev_browser_unauthenticated',

  // Session
  SessionNotFound: 'session_not_found',
  SessionInvalid: 'session_invalid',
  SessionNotActive: 'session_not_active',

  // Identity / credentials
  IdentityInvalidCredentials: 'identity_invalid_credentials',
  IdentitySuspended: 'identity_suspended',
  IdentityEmailNotVerified: 'identity_email_not_verified',
  IdentityNotFound: 'identity_not_found',
  IdentityEmailAlreadyRegistered: 'identity_email_already_registered',

  // Environment / auth method config
  AuthMethodDisabled: 'auth_method_disabled',

  // Password policy / tokens
  PasswordTooWeak: 'password_too_weak',
  PasswordBreached: 'password_breached',
  PasswordIncorrect: 'password_incorrect',
  TokenInvalidOrExpired: 'token_invalid_or_expired',
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

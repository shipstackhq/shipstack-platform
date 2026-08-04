import { HttpException, HttpStatus } from '@nestjs/common';
import { ErrorCode } from './error-codes';

// The ergonomic way to throw a coded FAPI exception, per
// docs/error-code-convention-task.md. AllExceptionsFilter reads `code`
// (and optional `longMessage`) off HttpException#getResponse() and emits
// Clerk's `{errors: [{message, long_message, code}]}` envelope whenever
// they're present, falling back to the plain-message shape for any
// ordinary HttpException that doesn't use this class.
//
// Usage:
//   throw new FapiException(HttpStatus.UNAUTHORIZED, ErrorCode.ClientRevoked, 'Client revoked');
//
// With an optional long_message for a fuller, user-facing explanation:
//   throw new FapiException(
//     HttpStatus.UNAUTHORIZED,
//     ErrorCode.DevBrowserUnauthenticated,
//     'Browser unauthenticated',
//     'Unable to authenticate this browser for your development instance. Check your cookies and try again.',
//   );
export class FapiException extends HttpException {
  constructor(status: HttpStatus, code: ErrorCode, message: string, longMessage?: string) {
    super({ message, longMessage, code }, status);
  }
}

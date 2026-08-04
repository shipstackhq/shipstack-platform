import { ApiProperty } from '@nestjs/swagger';
import { applyDecorators } from '@nestjs/common';
import { ApiResponse } from '@nestjs/swagger';
import { ErrorCode } from '../errors/error-codes';

// Documents the two response envelopes AllExceptionsFilter actually emits
// (see that file's own comment) — every FapiException-thrown error uses the
// coded shape below; anything else (ValidationPipe's 400s, an un-migrated
// plain HttpException/NotFoundException) falls back to the flat shape.
// Swagger only needs schema classes, never instantiated at runtime — these
// exist purely so @ApiResponse({ type: ... }) has something to point at.

class CodedErrorDetail {
  @ApiProperty({ example: 'Invalid or expired token' })
  message: string;

  @ApiProperty({ example: 'Invalid or expired token' })
  long_message: string;

  @ApiProperty({ enum: Object.values(ErrorCode), example: ErrorCode.TokenInvalidOrExpired })
  code: string;
}

export class CodedErrorEnvelope {
  @ApiProperty({ type: [CodedErrorDetail] })
  errors: CodedErrorDetail[];

  @ApiProperty({ example: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6' })
  clerk_trace_id: string;
}

export class FlatErrorEnvelope {
  @ApiProperty({ example: 400 })
  statusCode: number;

  @ApiProperty({ example: '2026-07-23T04:00:00.000Z' })
  timestamp: string;

  @ApiProperty({ example: '/api/v1/auth/client/sign_ins' })
  path: string;

  @ApiProperty({ example: 'identifier must be a string' })
  message: string | string[];
}

// One-line helper for the overwhelmingly common case: a coded FapiException
// error at a given status with a short human description of WHEN it fires
// (not a restatement of the code — the code is already in the schema).
// Controllers with an uncoded 400 (ValidationPipe) still add that
// separately via @ApiResponse({ status: 400, type: FlatErrorEnvelope }).
export function ApiCodedErrorResponse(status: number, description: string) {
  return applyDecorators(ApiResponse({ status, description, type: CodedErrorEnvelope }));
}

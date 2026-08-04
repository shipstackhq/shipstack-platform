import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Request, Response } from 'express';
import { randomBytes } from 'crypto';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const body = exception instanceof HttpException ? (exception.getResponse() as any) : undefined;

    const message = body?.message ?? (exception instanceof HttpException ? exception.message : 'Internal server error');

    // `code` is the opt-in signal: only exceptions built via FapiException
    // (or any HttpException whose response body happens to carry a `code`)
    // get the structured Clerk-shaped envelope below. Everything else falls
    // back to today's flat shape unchanged, so this is adoptable
    // incrementally across FAPI's ~77 throw sites rather than all at once.
    const code: string | undefined = typeof body?.code === 'string' ? body.code : undefined;

    if (status >= 500) {
      this.logger.error(
        `${request.method} ${request.url} → ${status}`,
        exception instanceof Error ? exception.stack : String(exception),
      );
    } else {
      this.logger.warn(`${request.method} ${request.url} → ${status}: ${JSON.stringify(message)}`);
    }

    if (code) {
      response.status(status).json({
        errors: [
          {
            message,
            long_message: body?.longMessage ?? message,
            code,
          },
        ],
        clerk_trace_id: randomBytes(16).toString('hex'),
      });
      return;
    }

    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
    });
  }
}

import { createParamDecorator, ExecutionContext } from '@nestjs/common';

// Copied verbatim from apps/platform-api/src/common/decorators/cookie-value.decorator.ts
export const CookieValue = createParamDecorator((cookieName: string, ctx: ExecutionContext): string | undefined => {
  const request = ctx.switchToHttp().getRequest();
  return request.cookies?.[cookieName];
});

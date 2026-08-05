import { IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// POST /auth/client/sessions/:id — matches Clerk's own single-route +
// action-body shape (clerk-js's Session.end()/remove() both POST to
// /client/sessions/:id with {action}) rather than separate :id/end,
// :id/remove paths — one route, one guard check, one place this auth
// lives, and adding a future terminal action is one more case, not a new
// controller method.
export class SessionActionDto {
  @ApiProperty({ enum: ['end', 'remove'], description: '"end" revokes but keeps the session visible; "remove" additionally signals "forget this session" for UI purposes.' })
  @IsIn(['end', 'remove']) action!: 'end' | 'remove';
}

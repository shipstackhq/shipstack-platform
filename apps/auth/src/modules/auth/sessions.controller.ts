import { BadRequestException, Body, Controller, Delete, Get, Param, Post, Req, UseGuards } from '@nestjs/common';
import { ApiBasicAuth, ApiCookieAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { SessionGuard } from '@/common/guards/session.guard';
import { ApiCodedErrorResponse } from '@/common/swagger/error-envelopes';
import { AuthService } from './auth.service';
import { SessionActionDto } from './dto/session-action.dto';

// /auth/client/sessions/* — client-as-root session lifecycle (see
// AuthController's class comment on the same philosophy for /auth/client
// itself). Every route here runs behind SessionGuard, which resolves
// req.client from the __client cookie / dev-browser pointer / backend-proxy
// relay exactly like every other client-scoped route — a session's
// ownership by that already-resolved client is the entire authorization
// model (see AuthService's "Session lifecycle" section comment).
//
// GET/POST/DELETE here intentionally never set or touch the __client
// cookie — unlike /auth/client and /auth/client/sign_ins|sign_ups, none of
// these routes mint or rotate a Client, only read/mutate a Session already
// scoped to one. Nothing here needs relayClient()'s pattern.
@ApiTags('Sessions')
@ApiCookieAuth('directModeCookie')
@ApiBasicAuth('backendProxyBasicAuth')
@Controller('auth/client/sessions')
@UseGuards(SessionGuard)
export class SessionsController {
  constructor(private auth: AuthService) {}

  @ApiOperation({ summary: 'Read a session', description: 'status downgrades to EXPIRED at read time once expiresAt has passed, even though the DB row\'s own status column may still say ACTIVE.' })
  @ApiResponse({ status: 200 })
  @ApiCodedErrorResponse(404, 'Unknown sessionId, or it belongs to a different client (never distinguished from unknown, to avoid leaking existence).')
  @Get(':id')
  async get(@Req() req: Request, @Param('id') id: string) {
    const client = (req as any).client;
    return this.auth.getSession(id, client.id);
  }

  // Matches Clerk's own DELETE /client/sessions (end every session for the
  // current client) — the bulk counterpart to end/:id. Reuses
  // AuthService.logout() (no sessionId → all ACTIVE sessions for the
  // client), the same implementation DELETE /auth/client itself calls, so
  // the two routes can never drift out of sync on what "end all sessions"
  // actually does.
  @ApiOperation({ summary: 'End every active session for the current client (bulk)' })
  @ApiResponse({ status: 200 })
  @Delete()
  async endAll(@Req() req: Request) {
    const client = (req as any).client;
    return this.auth.logout(client.id);
  }

  @ApiOperation({ summary: 'Heartbeat — bumps lastActiveAt only', description: 'Pure heartbeat: never mints a token, and (deliberately) not expiry-gated — ownership is the only authorization check here, unlike mint/refresh.' })
  @ApiResponse({ status: 201 })
  @ApiCodedErrorResponse(404, 'Unknown or unowned session.')
  @Post(':id/touch')
  async touch(@Req() req: Request, @Param('id') id: string) {
    const client = (req as any).client;
    return this.auth.touchSession(id, client.id);
  }

  // Matches Clerk's own POST /client/sessions/:id (action body) — see
  // SessionActionDto's own doc comment for why this replaced separate
  // :id/end and :id/remove routes.
  @ApiOperation({ summary: 'End or remove a single session', description: 'Clerk\'s own single-route + {action} body shape, not separate :id/end and :id/remove paths.' })
  @ApiResponse({ status: 201 })
  @ApiResponse({ status: 400, description: 'action is neither "end" nor "remove".' })
  @ApiCodedErrorResponse(404, 'Unknown or unowned session.')
  @Post(':id')
  async action(@Req() req: Request, @Param('id') id: string, @Body() dto: SessionActionDto) {
    const client = (req as any).client;
    if (dto.action === 'end') return this.auth.endSession(id, client.id);
    if (dto.action === 'remove') return this.auth.removeSession(id, client.id);
    throw new BadRequestException('Unsupported action');
  }

  @ApiOperation({
    summary: 'Mint a fresh access token for a specific session',
    description: 'The multi-session counterpart to POST /auth/refresh\'s "whichever session is active" scope — mints for exactly the session named by :id, regardless of which one the client currently considers active.',
  })
  @ApiResponse({ status: 201 })
  @ApiCodedErrorResponse(401, 'The session is not ACTIVE, or its expiresAt has already passed (session_not_active — same code either way).')
  @ApiCodedErrorResponse(404, 'Unknown or unowned session.')
  @Post(':id/tokens')
  async mintToken(@Req() req: Request, @Param('id') id: string) {
    const client = (req as any).client;
    return this.auth.mintSessionToken(id, client.id);
  }
}

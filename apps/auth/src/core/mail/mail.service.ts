import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

// Duplicated verbatim from apps/platform-api/src/core/mail/mail.service.ts
// per the migration plan's "duplicate now, don't extract" decision.
@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter | null = null;

  constructor() {
    const host = process.env.SMTP_HOST;
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

    if (host && user && pass) {
      this.transporter = nodemailer.createTransport({
        host,
        port: Number(process.env.SMTP_PORT ?? 587),
        secure: process.env.SMTP_SECURE === 'true',
        auth: { user, pass },
      });
    } else {
      this.logger.warn('SMTP not configured — emails will be logged to console only');
    }
  }

  async sendVerificationEmail(to: string, token: string, projectName?: string) {
    const subject = `Verify your email${projectName ? ` for ${projectName}` : ''}`;
    const text = `Please verify your email address.\n\nYour verification token: ${token}\n\nThis token expires in 24 hours.\n\nIf you did not create this account, ignore this email.`;

    if (!this.transporter) {
      this.logger.log(`[DEV] Verification email to ${to} — token: ${token}`);
      return;
    }

    await this.transporter.sendMail({
      from: process.env.SMTP_FROM ?? 'noreply@shipstack.run',
      to,
      subject,
      text,
    });
  }

  // EMAIL_CODE strategy's own send step (Phase 5 —
  // docs/unified-attempt-architecture.md) — a short numeric code, not a
  // long opaque token like the other two methods here, since the user
  // types this one back manually rather than clicking a link.
  async sendVerificationCode(to: string, code: string, projectName?: string) {
    const subject = `Your verification code${projectName ? ` for ${projectName}` : ''}`;
    const text = `Your verification code is: ${code}\n\nThis code expires in 10 minutes.\n\nIf you did not request this, ignore this email.`;

    if (!this.transporter) {
      this.logger.log(`[DEV] Verification code email to ${to} — code: ${code}`);
      return;
    }

    await this.transporter.sendMail({
      from: process.env.SMTP_FROM ?? 'noreply@shipstack.run',
      to,
      subject,
      text,
    });
  }

  async sendPasswordReset(to: string, token: string, projectName?: string) {
    const subject = `Reset your password${projectName ? ` for ${projectName}` : ''}`;
    const text = `You requested a password reset.\n\nYour reset token: ${token}\n\nThis token expires in 30 minutes.\n\nIf you did not request this, ignore this email.`;

    if (!this.transporter) {
      this.logger.log(`[DEV] Password reset email to ${to} — token: ${token}`);
      return;
    }

    await this.transporter.sendMail({
      from: process.env.SMTP_FROM ?? 'noreply@shipstack.run',
      to,
      subject,
      text,
    });
  }
}

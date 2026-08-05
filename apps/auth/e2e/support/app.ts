import * as dotenv from 'dotenv';
import * as path from 'path';

// Loaded before ANY other import in this file (including AppModule) reads
// process.env — dotenv/config's default behavior (imported transitively via
// app.module.ts/main.ts) would otherwise win by loading apps/fapi/.env
// first were this file structured any other way. override:true because
// jest may have already loaded a .env via some other path by the time this
// runs; explicit intent beats load order here.
dotenv.config({ path: path.resolve(__dirname, '../.env.test'), override: true });

import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import { AppModule } from '../../src/app.module';
import { AllExceptionsFilter } from '../../src/common/filters/all-exceptions.filter';
import { MailService } from '../../src/core/mail/mail.service';
import { FakeMailService } from './fake-mail.service';

// Mirrors main.ts's bootstrap() exactly (setGlobalPrefix, cookieParser,
// ValidationPipe, AllExceptionsFilter) MINUS app.listen() and the
// origin-enforcement middleware. Origin enforcement is deliberately
// omitted here — every e2e request would need an Origin header matching a
// seeded environment's allowedOrigins or it 403s by default-fail-open-only-
// when-empty logic (main.ts's own documented gap), which is more test
// friction than value at this stage. Add it back as its own harness
// variant if/when a test specifically needs to exercise CORS behavior.
//
// MailService is overridden with FakeMailService (@nestjs/testing's own
// overrideProvider mechanism — see fake-mail.service.ts's own doc comment
// for why this is necessary, not just convenient: EMAIL_CODE's plaintext
// code is never persisted anywhere, only its hash). Every existing test's
// `createTestApp()` call is unaffected by this — the override is transparent
// to any test that doesn't care about mail. A test that DOES need the
// captured code retrieves the SAME instance the app is using via
// `app.get(MailService)` — keyed by the ORIGINAL token, not FakeMailService's
// own class (overrideProvider swaps what the MailService token resolves to,
// it does not additionally register FakeMailService as its own token —
// `app.get(FakeMailService)` throws "provider does not exist").
export async function createTestApp(): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  })
    .overrideProvider(MailService)
    .useValue(new FakeMailService())
    .compile();

  const app = moduleRef.createNestApplication();
  app.setGlobalPrefix('api/v1');
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  app.useGlobalFilters(new AllExceptionsFilter());

  await app.init();
  return app;
}

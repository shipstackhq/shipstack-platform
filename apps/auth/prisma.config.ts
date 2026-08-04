import 'dotenv/config';
import { defineConfig } from 'prisma/config';

// Platform schema: the tables Auth owns. Used for `prisma generate` and
// `prisma db push` against PLATFORM_DATABASE_URL.
export default defineConfig({
  schema: 'prisma/platform.prisma',
  datasource: { url: process.env.PLATFORM_DATABASE_URL ?? '' },
});

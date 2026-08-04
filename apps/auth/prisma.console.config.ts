import 'dotenv/config';
import { defineConfig } from 'prisma/config';

// Console read model: the environment and auth-method tables Auth reads but
// does not own. Used only for generating the read client and for test setup.
// Production reads go through the read-only grant on CONSOLE_DATABASE_URL.
export default defineConfig({
  schema: 'prisma/console.prisma',
  datasource: { url: process.env.CONSOLE_DATABASE_URL ?? '' },
});

-- ─────────────────────────────────────────────────────────────────────────────
-- DB grants — run this after every migrate reset on either schema.
--
-- Roles
--   console_user   — console-api app user (read/write console schema)
--   platform_user  — platform-api app user (read/write platform schema,
--                    read-only on console schema for project config lookups)
--   shipstack      — superuser used to run migrations
--
-- Run via db-reset.sh (recommended) or manually:
--   cd apps/console-api
--   DATABASE_URL="postgresql://shipstack:shipstack@localhost:5432/shipstack?schema=console" \
--   npx prisma db execute --file ../../scripts/db-grants.sql
--
-- WARNING: console and platform schemas must always be reset together.
-- Resetting only console leaves platform identities pointing to stale environment IDs
-- (identity.environmentId will not match the new console environment IDs → exchange fails).
-- ─────────────────────────────────────────────────────────────────────────────

-- ── console schema ────────────────────────────────────────────────────────────

GRANT USAGE ON SCHEMA console TO console_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA console TO console_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA console TO console_user;
-- Cover objects created by the shipstack superuser (migrations run as shipstack)
ALTER DEFAULT PRIVILEGES FOR ROLE shipstack IN SCHEMA console GRANT ALL ON TABLES TO console_user;
ALTER DEFAULT PRIVILEGES FOR ROLE shipstack IN SCHEMA console GRANT ALL ON SEQUENCES TO console_user;

-- platform-api reads and writes console schema (project config lookups + subscriptions)
GRANT USAGE ON SCHEMA console TO platform_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA console TO platform_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA console TO platform_user;
ALTER DEFAULT PRIVILEGES FOR ROLE shipstack IN SCHEMA console GRANT ALL ON TABLES TO platform_user;
ALTER DEFAULT PRIVILEGES FOR ROLE shipstack IN SCHEMA console GRANT ALL ON SEQUENCES TO platform_user;

-- ── platform schema ───────────────────────────────────────────────────────────

GRANT USAGE ON SCHEMA platform TO platform_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA platform TO platform_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA platform TO platform_user;
ALTER DEFAULT PRIVILEGES FOR ROLE shipstack IN SCHEMA platform GRANT ALL ON TABLES TO platform_user;
ALTER DEFAULT PRIVILEGES FOR ROLE shipstack IN SCHEMA platform GRANT ALL ON SEQUENCES TO platform_user;

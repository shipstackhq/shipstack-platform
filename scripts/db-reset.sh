#!/usr/bin/env bash
# Usage: ./scripts/db-reset.sh
# Bypasses Prisma and wipes both schemas directly via Docker, then runs fresh migrations.
# Always run from the repo root.

set -e

echo "→ Dropping and recreating schemas via Docker..."
docker exec shipstackrun-postgres-1 psql -U shipstack -d shipstack -c "
  DROP SCHEMA IF EXISTS console CASCADE;
  DROP SCHEMA IF EXISTS platform CASCADE;
  DROP SCHEMA IF EXISTS console_shadow CASCADE;
  CREATE SCHEMA console;
  CREATE SCHEMA platform;
"

echo "→ Creating roles (idempotent)..."
docker exec shipstackrun-postgres-1 psql -U shipstack -d shipstack -c "
  DO \$\$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'console_user') THEN
      CREATE ROLE console_user WITH LOGIN PASSWORD 'console_pass';
    ELSE
      ALTER ROLE console_user WITH PASSWORD 'console_pass';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'platform_user') THEN
      CREATE ROLE platform_user WITH LOGIN PASSWORD 'platform_pass';
    ELSE
      ALTER ROLE platform_user WITH PASSWORD 'platform_pass';
    END IF;
  END \$\$;
"

echo "→ Running console migrations..."
cd apps/console-api
DATABASE_URL="postgresql://shipstack:shipstack@localhost:5432/shipstack?schema=console" \
  npx prisma migrate deploy
cd ../..

echo "→ Running platform migrations..."
cd apps/bapi
PLATFORM_DATABASE_URL="postgresql://shipstack:shipstack@localhost:5432/shipstack?schema=platform" \
  npx prisma migrate deploy
cd ../..

echo "→ Applying grants..."
cd apps/console-api
DATABASE_URL="postgresql://shipstack:shipstack@localhost:5432/shipstack?schema=console" \
  npx prisma db execute --file ../../scripts/db-grants.sql
cd ../..

cd apps/bapi
PLATFORM_DATABASE_URL="postgresql://shipstack:shipstack@localhost:5432/shipstack?schema=platform" \
  npx prisma db execute --stdin <<'GRANTS'
GRANT USAGE ON SCHEMA platform TO platform_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA platform TO platform_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA platform TO platform_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA platform GRANT ALL ON TABLES TO platform_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA platform GRANT ALL ON SEQUENCES TO platform_user;
GRANTS
cd ../..

echo "✓ Done. DB is completely clean, migrations applied, permissions set."

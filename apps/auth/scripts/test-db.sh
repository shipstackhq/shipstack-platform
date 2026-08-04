#!/usr/bin/env bash
# Sets up a throwaway Postgres for the auth e2e suite and pushes both schemas.
#
#   ./scripts/test-db.sh
#
# Starts a Postgres 16 container on port 5433 (never the dev port), creates
# shipstack_test with console and platform schemas, pushes the Auth schemas,
# and pushes the Console test fixture (see e2e/support/console-fixture.prisma).
# Re-running drops and rebuilds the test database from scratch.
set -euo pipefail

CONTAINER=shipstack-auth-test
PORT=5433
PW=postgres
DB=shipstack_test
cd "$(dirname "$0")/.."

if ! docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=$PW -p $PORT:5432 postgres:16-alpine >/dev/null
fi
docker start "$CONTAINER" >/dev/null
for _ in $(seq 1 30); do
  docker exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

docker exec "$CONTAINER" psql -U postgres -qc "DROP DATABASE IF EXISTS $DB;" -c "CREATE DATABASE $DB;"
docker exec "$CONTAINER" psql -U postgres -d $DB -qc "CREATE SCHEMA console; CREATE SCHEMA platform;"

export CONSOLE_DATABASE_URL="postgresql://postgres:$PW@localhost:$PORT/$DB?schema=console"
export PLATFORM_DATABASE_URL="postgresql://postgres:$PW@localhost:$PORT/$DB?schema=platform"

npx prisma db push --config=prisma.config.ts
npx prisma db push --config=prisma.console.config.ts --schema=e2e/support/console-fixture.prisma

echo "Test database ready on localhost:$PORT/$DB"

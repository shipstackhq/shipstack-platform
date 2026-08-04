// Platform Database Client & Types (Identities, Attempts, Sessions, Tokens, etc.)
export * from './generated/platform';
export { PrismaClient as PlatformPrismaClient } from './generated/platform';

// Console Database Client & Types (Environments, Workspaces, Projects, Users, etc.)
export * as Console from './generated/console';
export { PrismaClient as ConsolePrismaClient } from './generated/console';

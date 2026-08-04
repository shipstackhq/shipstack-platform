import { Global, Module } from '@nestjs/common';
import { PlatformPrismaService } from './platform-prisma.service';
import { ConsolePrismaService } from './console-prisma.service';
import { BackendProxyDetector } from '@/common/guards/backend-proxy-detector';

// BackendProxyDetector lives here (not its own module) because every guard
// that needs it (EnvironmentGuard, SessionGuard) is instantiated via
// @UseGuards(SomeGuard) across many
// independent feature modules (auth, config, quota, subscriptions) —
// @UseGuards() only resolves a guard's constructor deps through the
// enclosing module's own provider graph, it does NOT auto-instantiate
// arbitrary @Injectable() classes just because they exist somewhere in the
// codebase (confirmed the hard way: a real Nest boot failure,
// "Nest can't resolve dependencies of the SessionGuard" pointing at
// BackendProxyDetector, before this was added here). PrismaModule is
// already @Global() and already how ConsolePrismaService reaches every one
// of those modules — same treatment, same reason.
@Global()
@Module({
  providers: [PlatformPrismaService, ConsolePrismaService, BackendProxyDetector],
  exports: [PlatformPrismaService, ConsolePrismaService, BackendProxyDetector],
})
export class PrismaModule {}

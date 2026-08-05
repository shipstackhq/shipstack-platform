import { Injectable, NotFoundException } from '@nestjs/common';
import { ConsolePrismaService } from '@/core/database/console-prisma.service';
import { AuthMethod } from '@/generated/platform/enums';

export interface EnvironmentResource {
  authMethods: {
    emailPassword: boolean
    google: boolean
  }
  password: {
    minLength: number
    requirements: string
    preventLeakedPasswords: boolean
    minPasswordStrength: number | null
  }
  requireEmailVerification: boolean
  nameFields: {
    collect: boolean
    required: boolean
  }
  allowSelfDeletion: boolean
}

// Renamed from ConfigService/config.module (GET /config -> GET /environment)
// per docs/environment-resource-task.md — the one place all per-project
// auth/policy config lives, mirroring Clerk's single GET /v1/environment
// (EnvironmentResource) read by both the client SDK and, here, FAPI's own
// enforcement code. AuthService.getEnvConfig used to run a second,
// independent query for the same Environment row (see its own comment) —
// it now delegates to getConfig() below so there is exactly one query
// shape, not two.
//
// Takes environmentId, not publishableKey — callers (EnvironmentGuard for
// the controller, AuthService/AttemptsService internally) already resolved
// req.environment (existence, SUSPENDED check) from the Host header — see
// resolve-slug-from-host.ts.
@Injectable()
export class EnvironmentService {
  constructor(private console: ConsolePrismaService) {}

  async getConfig(environmentId: string): Promise<EnvironmentResource & { accessTokenTtl: number; refreshTokenTtl: number }> {
    const environment = await this.console.environment.findUnique({
      where: { id: environmentId },
      include: {
        authMethodConfigs: { select: { method: true, enabled: true } },
      },
    });

    if (!environment) throw new NotFoundException('Unknown environment');

    return {
      authMethods: {
        emailPassword: this.isEnabledOn(environment.authMethodConfigs, 'EMAIL_PASSWORD'),
        google: this.isEnabledOn(environment.authMethodConfigs, 'GOOGLE'),
      },
      password: {
        minLength: environment.minPasswordLength,
        requirements: environment.passwordRequirements,
        preventLeakedPasswords: environment.preventLeakedPasswords,
        minPasswordStrength: environment.minPasswordStrength,
      },
      requireEmailVerification: environment.requireEmailVerification,
      nameFields: {
        collect: environment.collectFirstLastName,
        required: environment.requireFirstLastName,
      },
      allowSelfDeletion: environment.allowSelfDeletion,
      // Session-minting internals, not developer-facing config discovery —
      // included in this internal getConfig() return (AttemptsService/
      // SignUpAttemptsService/AuthService need them) but deliberately
      // omitted from EnvironmentResource / GET /environment's public shape.
      accessTokenTtl: environment.accessTokenTtl,
      refreshTokenTtl: environment.refreshTokenTtl,
    };
  }

  async getPublicResource(environmentId: string): Promise<EnvironmentResource> {
    const { accessTokenTtl, refreshTokenTtl, ...resource } = await this.getConfig(environmentId);
    return resource;
  }

  // Microsoft OAuth is out of v1 (D4). Its strategy is deleted. The DB enum value
  // stays, because existing rows may still reference it, so enforcement
  // hard-denies it instead of falling through to the missing-row default — an unconfigured method
  // being enabled-by-default is fine for a method that's actually
  // supported (EMAIL_CODE); it's not an acceptable way to leave an
  // unsupported, untested one reachable.
  private static readonly DISABLED_METHODS: ReadonlySet<string> = new Set(['MICROSOFT']);

  // Enforcement default: a method with no AuthMethodConfig row at all is
  // treated as ENABLED, matching the DB column's own `@default(true)` (see
  // console.prisma's AuthMethodConfig.enabled) and console-api's
  // ProjectsService.createProject, which only ever seeds explicit rows for
  // EMAIL_PASSWORD (enabled) and GOOGLE (disabled) — EMAIL_CODE is left
  // unconfigured and has always worked in production. The old
  // discovery-only ConfigService.isEnabled defaulted missing rows to
  // `false`, which was never exercised for enforcement (nothing checked
  // it) — doing that for real here would silently break every existing
  // e2e test and every real environment's EMAIL_CODE sign-in, since none
  // of them seed AuthMethodConfig rows for it. MICROSOFT is the one
  // explicit exception — see DISABLED_METHODS above.
  private isEnabledOn(configs: { method: string; enabled: boolean }[], method: string): boolean {
    if (EnvironmentService.DISABLED_METHODS.has(method)) return false;
    return configs.find(c => c.method === method)?.enabled ?? true;
  }

  async isEnabled(environmentId: string, method: AuthMethod): Promise<boolean> {
    if (EnvironmentService.DISABLED_METHODS.has(method)) return false;
    const environment = await this.console.environment.findUniqueOrThrow({
      where: { id: environmentId },
      include: {
        authMethodConfigs: { where: { method }, select: { enabled: true } },
      },
    });
    return environment.authMethodConfigs[0]?.enabled ?? true;
  }
}

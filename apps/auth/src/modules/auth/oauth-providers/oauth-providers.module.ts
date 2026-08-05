import { Module } from '@nestjs/common';
import { OAuthProvidersService } from './oauth-providers.service';
import { PrismaModule } from '@/core/database/prisma.module';
import { EncryptionModule } from '@/core/encryption/encryption.module';

@Module({
  imports: [PrismaModule, EncryptionModule],
  providers: [OAuthProvidersService],
  exports: [OAuthProvidersService],
})
export class OAuthProvidersModule {}

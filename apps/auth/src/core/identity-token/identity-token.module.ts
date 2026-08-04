import { Module } from '@nestjs/common';
import { IdentityTokenService } from './identity-token.service';
import { PrismaModule } from '@/core/database/prisma.module';
import { EncryptionModule } from '@/core/encryption/encryption.module';

@Module({
  imports: [PrismaModule, EncryptionModule],
  providers: [IdentityTokenService],
  exports: [IdentityTokenService],
})
export class IdentityTokenModule {}

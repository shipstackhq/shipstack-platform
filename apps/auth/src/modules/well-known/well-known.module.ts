import { Module } from '@nestjs/common';
import { WellKnownController } from './well-known.controller';
import { IdentityTokenModule } from '@/core/identity-token/identity-token.module';

@Module({
  imports: [IdentityTokenModule],
  controllers: [WellKnownController],
})
export class WellKnownModule {}

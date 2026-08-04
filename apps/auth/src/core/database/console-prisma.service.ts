import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@/generated/console/client';
import { PrismaPg } from '@prisma/adapter-pg';

@Injectable()
export class ConsolePrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    const adapter = new PrismaPg(
      { connectionString: process.env.CONSOLE_DATABASE_URL },
      { schema: 'console' },
    );
    super({ adapter });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}

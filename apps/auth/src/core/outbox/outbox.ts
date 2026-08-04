import type { Prisma } from "@/generated/platform/client";
import { generateId } from '@/common/utils/id';
import type { PlatformPrismaService } from '@/core/database/platform-prisma.service';

// Writes one event to the transactional outbox (decision D14). Call it with the
// same client, or inside the same transaction, as the change that caused the
// event, so the event exists if and only if the change committed.
//
// Consumers must be idempotent: the relay can publish an event more than once,
// so the id here is the deduplication key.
export interface OutboxEventInput {
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  payload: Prisma.InputJsonObject;
}

export async function enqueueOutboxEvent(
  db: Pick<PlatformPrismaService, 'outboxEvent'>,
  event: OutboxEventInput,
): Promise<void> {
  await db.outboxEvent.create({
    data: {
      id: generateId(),
      aggregateType: event.aggregateType,
      aggregateId: event.aggregateId,
      eventType: event.eventType,
      payload: event.payload,
    },
  });
}

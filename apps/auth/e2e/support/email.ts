import { randomBytes } from 'crypto';

// Date.now() alone is only millisecond-resolution — safe today given every
// test gets its own freshly-seeded, freshly-torn-down Environment
// (identifier uniqueness is scoped per environmentId), but not
// collision-proof: nothing stops two tests (now or in a future suite that
// shares one seeded environment across several `it()` blocks to avoid
// reseeding per test) from generating the same email in the same
// millisecond. The random suffix removes that risk outright rather than
// relying on timing.
export function uniqueEmail(prefix = 'e2e'): string {
  const suffix = randomBytes(4).toString('hex');
  return `${prefix}-${Date.now()}-${suffix}@example.com`;
}

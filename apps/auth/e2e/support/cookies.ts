// supertest/Node type `set-cookie` as `string | string[] | undefined` —
// a single Set-Cookie header CAN legitimately arrive as a plain string,
// not just an array (only .find() on an array works, which is what the
// naive `res.headers['set-cookie']?.find(...)` pattern silently assumed
// and tsc correctly flagged: TS2339, Property 'find' does not exist on
// type 'string'). Normalizes to an array first so callers never have to
// think about which shape they got.
export function findSetCookie(headers: Record<string, string | string[] | undefined>, namePrefix: string): string | undefined {
  const raw = headers['set-cookie'];
  if (!raw) return undefined;
  const cookies = Array.isArray(raw) ? raw : [raw];
  return cookies.find(c => c.startsWith(namePrefix));
}

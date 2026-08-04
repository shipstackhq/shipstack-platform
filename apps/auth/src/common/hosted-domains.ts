// The domain suffixes a Shipstack-hosted auth page can live under. Both the
// Host-header slug parser (resolve-slug-from-host.ts) and the publishable-key
// decoder (decode-domain-from-publishable-key.ts) read this single list, so a
// new suffix only has to be added here.
//
// `.stack.shipstack.development` is local dev through Traefik (see
// docs/README.md, section 3).
export const HOSTED_AUTH_DOMAIN_SUFFIXES = [
  '.stack.shipstack.run',
  '.stack.dev.shipstack.run',
  '.stack.shipstack.development',
] as const;

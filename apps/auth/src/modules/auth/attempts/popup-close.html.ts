// Shared popup-closer page, rendered by OAuthCallbackController when an
// attempt's redirectMode is POPUP (docs/unified-attempt-architecture.md,
// "popup mode" addendum). Mirrors Clerk's own Account Portal
// `/popup-callback` route in spirit (postMessage the result to window.opener,
// then close) — except we render it directly from FAPI's own callback
// response rather than bouncing through a separate hosted page, since we
// have no multi-tenant Account Portal to route through. This is also what
// the LEGACY oauth.controller.ts's googleCallback() already did inline for
// `mode === 'popup'`; extracted here so both the legacy route and the new
// attempt-based one can share it without duplicating the script.
export function renderPopupCloseHtml(payload: Record<string, unknown>, targetOrigin: string): string {
  return `<!DOCTYPE html>
<html>
<head><title>Signing in…</title></head>
<body>
<script>
  var targetOrigin = ${JSON.stringify(targetOrigin)};
  var payload = ${JSON.stringify(payload)};

  window.addEventListener('beforeunload', function() {
    if (window.opener) {
      window.opener.postMessage({ type: 'SHIPSTACK_POPUP_CLOSED' }, targetOrigin);
    }
  });

  if (window.opener) {
    window.opener.postMessage(payload, targetOrigin);
  }
  window.close();
</script>
</body>
</html>`;
}

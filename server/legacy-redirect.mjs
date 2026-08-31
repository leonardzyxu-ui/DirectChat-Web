const CANONICAL_ORIGIN = "https://directchat.srv1921833.hstgr.cloud";

/**
 * Build the one permitted legacy-public redirect destination. Invalid
 * configuration is intentionally ignored: this is a pin, not a general
 * redirect mechanism.
 */
export function legacyRedirectLocation(configuredTarget, requestURL) {
  const candidate = String(configuredTarget || "").trim();
  let target;
  try {
    target = new URL(candidate);
    if (
      target.origin !== CANONICAL_ORIGIN ||
      target.username ||
      target.password ||
      target.pathname !== "/" ||
      target.search ||
      target.hash
    ) return null;
    const incoming = new URL(requestURL || "/", "https://legacy.invalid");
    const path = incoming.pathname.startsWith("/") ? incoming.pathname : `/${incoming.pathname}`;
    return new URL(`${path}${incoming.search}`, `${CANONICAL_ORIGIN}/`).toString();
  } catch {
    return null;
  }
}

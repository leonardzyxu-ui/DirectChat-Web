const HTTPS_URL = /^https:\/\//i;

/**
 * Build the one permitted legacy-public redirect destination.  Invalid or
 * non-HTTPS configuration is intentionally ignored so a bad Render variable
 * cannot turn the old service into an open redirect.
 */
export function legacyRedirectLocation(configuredTarget, requestURL) {
  const candidate = String(configuredTarget || "").trim();
  if (!HTTPS_URL.test(candidate)) return null;
  let target;
  try {
    target = new URL(candidate);
    if (target.protocol !== "https:") return null;
    const incoming = new URL(requestURL || "/", "https://legacy.invalid");
    return new URL(`${incoming.pathname}${incoming.search}`, target).toString();
  } catch {
    return null;
  }
}

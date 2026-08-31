// Render-side, one-shot exporter. It holds vault objects only in memory long
// enough to AES-GCM seal and HTTPS POST them to the configured VPS receiver.
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { collectLegacyAccountVaults } from "../scripts/export-legacy-accounts.mjs";

const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const FORMAT = "directchat-legacy-vault-transport-v1";

export function vaultPushConfiguration(environment = process.env) {
  const sourceOrigin = exactHTTPSOrigin(environment.DIRECTCHAT_LEGACY_MIGRATION_ORIGIN || "");
  const importURL = exactHTTPSURL(environment.DIRECTCHAT_LEGACY_VAULT_IMPORT_URL || "");
  const importToken = String(environment.DIRECTCHAT_LEGACY_VAULT_IMPORT_TOKEN || "");
  const transportKey = String(environment.DIRECTCHAT_LEGACY_VAULT_TRANSPORT_KEY || "");
  return environment.DIRECTCHAT_LEGACY_VAULT_EXPORT_ENABLED === "true" && sourceOrigin && importURL && TOKEN.test(importToken) && validKey(transportKey)
    ? { sourceOrigin, importURL, importToken, transportKey } : null;
}

export async function pushLegacyAccountVaults({ redis, fetchImpl = fetch, environment = process.env, now = Date.now() }) {
  const config = vaultPushConfiguration(environment); if (!config) throw new Error("legacy vault push unavailable");
  const bundle = await collectLegacyAccountVaults(redis);
  const payload = seal(bundle, config.transportKey, now);
  const response = await fetchImpl(config.importURL, { method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${config.importToken}`, "Origin": config.sourceOrigin }, body: JSON.stringify(payload) });
  if (!response.ok) throw new Error("legacy vault receiver rejected export");
  const result = await response.json();
  if (!result?.ok || JSON.stringify(result.aggregate) !== JSON.stringify(payload.aggregate)) throw new Error("legacy vault receiver reconciliation failed");
  return { aggregate: payload.aggregate, imported: Number(result.imported || 0), duplicates: Number(result.duplicates || 0), before: result.before, after: result.after };
}

function seal(bundle, keyValue, now) {
  const key = Buffer.from(keyValue, "base64url");
  const plaintext = Buffer.from(JSON.stringify(bundle));
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, nonce), ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { format: FORMAT, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 10 * 60 * 1000).toISOString(), aggregate: bundle.aggregate, bundleDigest: digest(plaintext), nonceBase64: nonce.toString("base64url"), ciphertextBase64: ciphertext.toString("base64url"), authTagBase64: cipher.getAuthTag().toString("base64url") };
}
function exactHTTPSOrigin(value) { try { const url = new URL(String(value || "")); return url.protocol === "https:" && !url.username && !url.password && !url.port && url.pathname === "/" && !url.search && !url.hash ? url.origin : ""; } catch { return ""; } }
function exactHTTPSURL(value) { try { const url = new URL(String(value || "")); return url.origin === "https://directchat.srv1921833.hstgr.cloud" && !url.username && !url.password && !url.port && !url.search && !url.hash && url.pathname === "/api/internal/legacy-vault-import" ? url.toString() : ""; } catch { return ""; } }
function validKey(value) { try { return B64URL.test(value) && Buffer.from(value, "base64url").length === 32; } catch { return false; } }
function digest(value) { return createHash("sha256").update(value).digest("hex"); }

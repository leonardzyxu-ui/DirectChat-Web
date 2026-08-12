import test from "node:test";
import assert from "node:assert/strict";
import { pushLegacyAccountVaults, vaultPushConfiguration } from "./legacy-vault-push.mjs";

const key = "B".repeat(43), token = "A".repeat(43);
const environment = {
  DIRECTCHAT_LEGACY_VAULT_EXPORT_ENABLED: "true",
  DIRECTCHAT_LEGACY_MIGRATION_ORIGIN: "https://directchat-relay.onrender.com",
  DIRECTCHAT_LEGACY_VAULT_IMPORT_URL: "https://directchat.srv1807979.hstgr.cloud/api/internal/legacy-vault-import",
  DIRECTCHAT_LEGACY_VAULT_IMPORT_TOKEN: token,
  DIRECTCHAT_LEGACY_VAULT_TRANSPORT_KEY: key
};

test("sealed vault push uses exact HTTPS receiver/origin and returns aggregate-only reconciliation", async () => {
  const redis = syntheticRedis(); let captured;
  const result = await pushLegacyAccountVaults({ redis, environment, fetchImpl: async (url, request) => {
    captured = { url, headers: request.headers, payload: JSON.parse(request.body) };
    return { ok: true, json: async () => ({ ok: true, aggregate: JSON.parse(request.body).aggregate, imported: 1, duplicates: 0, before: { users: 0 }, after: { users: 1 } }) };
  } });
  assert.equal(captured.url, environment.DIRECTCHAT_LEGACY_VAULT_IMPORT_URL);
  assert.equal(captured.headers.Origin, environment.DIRECTCHAT_LEGACY_MIGRATION_ORIGIN);
  assert.equal(captured.headers.Authorization, `Bearer ${token}`);
  assert.equal(captured.payload.format, "directchat-legacy-vault-transport-v1");
  assert.equal(typeof captured.payload.ciphertextBase64, "string");
  assert.equal(JSON.stringify(captured.payload).includes("synthetic-vault-ciphertext"), false);
  assert.deepEqual(result.aggregate, { indexedUsers: 1, accounts: 1, digest: result.aggregate.digest });
});

test("vault push fails closed for a lookalike receiver, incomplete config, and receiver reconciliation mismatch", async () => {
  assert.equal(vaultPushConfiguration({ ...environment, DIRECTCHAT_LEGACY_VAULT_IMPORT_URL: "https://directchat.srv1807979.hstgr.cloud.evil/api/internal/legacy-vault-import" }), null);
  await assert.rejects(() => pushLegacyAccountVaults({ redis: syntheticRedis(), environment, fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true, aggregate: { indexedUsers: 9 } }) }) }), /reconciliation/);
});

function syntheticRedis() {
  const record = { profile: { userID: "DC-LEGACY01", publicKeyBase64: "synthetic-public" }, accountVault: { userID: "DC-LEGACY01", publicKeyBase64: "synthetic-public", authVerifierBase64: "synthetic-verifier", kdf: { algorithm: "PBKDF2-HMAC-SHA256", iterations: 250000, authSaltBase64: "synthetic-auth-salt", vaultSaltBase64: "synthetic-vault-salt" }, vault: { nonceBase64: "synthetic-vault-nonce", ciphertextBase64: "synthetic-vault-ciphertext" } }, accountDevices: [] };
  return { smembers: async key => key === "directchat:users" ? ["DC-LEGACY01"] : [], get: async key => key === "directchat:user:DC-LEGACY01" ? record : null };
}

// Run only inside the Render service environment. Never logs records, IDs,
// vaults, verifiers, ciphertext, Safety Codes, keys, or message data.
import { createHash } from "node:crypto";
import { Redis } from "@upstash/redis";

const digest = value => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const validID = value => /^[A-Z0-9-]{6,40}$/.test(String(value || ""));

export async function collectLegacyAccountVaults(redis) {
  const ids = await redis.smembers("directchat:users");
  if (!Array.isArray(ids)) throw new Error("legacy user index malformed");
  const accounts = [];
  for (const id of ids) {
    if (!validID(id)) throw new Error("legacy user index invalid");
    const raw = await redis.get(`directchat:user:${id}`);
    let record; try { record = typeof raw === "string" ? JSON.parse(raw) : raw; } catch { throw new Error("legacy user record malformed"); }
    const vault = record?.accountVault, profile = record?.profile;
    if (!vault || !profile || vault.userID !== id || profile.userID !== id || vault.publicKeyBase64 !== profile.publicKeyBase64 || !vault.authVerifierBase64 || !vault.kdf?.authSaltBase64 || !vault.kdf?.vaultSaltBase64 || !vault.vault?.nonceBase64 || !vault.vault?.ciphertextBase64 || vault.kdf.algorithm !== "PBKDF2-HMAC-SHA256" || vault.kdf.iterations !== 250000) throw new Error("legacy encrypted account record invalid");
    accounts.push({ userID: id, record: { profile, accountVault: vault, accountDevices: Array.isArray(record.accountDevices) ? record.accountDevices : [] } });
  }
  accounts.sort((a,b) => a.userID.localeCompare(b.userID));
  return { format: "directchat-account-export-v1", indexedUsers: ids.length, accounts, aggregate: { indexedUsers: ids.length, accounts: accounts.length, digest: digest(accounts.map(item => ({ idHash: digest(item.userID), vaultHash: digest(item.record.accountVault), profileHash: digest(item.record.profile) }))) } };
}

if (process.argv[1]?.endsWith("export-legacy-accounts.mjs")) collectLegacyAccountVaults(Redis.fromEnv()).then(result => console.log(JSON.stringify({ ok: true, ...result.aggregate }))).catch(error => { console.error(error.message); process.exitCode = 1; });

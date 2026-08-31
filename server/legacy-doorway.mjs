// Old-origin only. The VPS owns receipt persistence and redemption.
export function migrationConfig(env = process.env) {
  const oldOrigin = exactOrigin(env.DIRECTCHAT_LEGACY_MIGRATION_ORIGIN || "");
  const targetOrigin = exactOrigin(env.DIRECTCHAT_LEGACY_MIGRATION_TARGET || "");
  return oldOrigin && targetOrigin ? { oldOrigin, targetOrigin } : null;
}
function exactOrigin(value) { try { const url = new URL(String(value || "")); return url.protocol === "https:" && !url.username && !url.password && !url.port && url.pathname === "/" && !url.search && !url.hash ? url.origin : ""; } catch { return ""; } }
export function legacyDoorwayHTML(config) {
  const safe = JSON.stringify(config).replaceAll("<", "\\u003c");
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Move DirectChat</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f5f9;font:16px system-ui;color:#101828}.card{width:min(440px,calc(100% - 40px));padding:28px;border:1px solid #d9e0eb;border-radius:20px;background:#fff}button{width:100%;padding:13px;border:0;border-radius:12px;background:#0a84ff;color:#fff;font-weight:700;font-size:16px}</style><main class="card"><h1>Move DirectChat securely</h1><p>Your account can move to the new secure service in one step.</p><button id="move">Move my DirectChat</button><p id="status" role="status"></p></main><script>(${doorway.toString()})(${safe},(${base64URLFromBytes.toString()}))</script>`;
}
export function base64URLFromBytes(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function doorway(config, b64) {
  const button = document.getElementById("move");
  const status = document.getElementById("status");
  const enc = new TextEncoder();
  const sha = async value => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", typeof value === "string" ? enc.encode(value) : value))).map(x => x.toString(16).padStart(2, "0")).join("");
  const random = length => {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  };
  const request = requestObject => new Promise((resolve, reject) => {
    requestObject.onsuccess = () => resolve(requestObject.result);
    requestObject.onerror = () => reject(requestObject.error);
  });
  const done = transaction => new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  button.onclick = async () => {
    button.disabled = true;
    status.textContent = "Preparing your secure move…";
    try {
      const opening = indexedDB.open("directchat-web", 2);
      const db = await request(opening);
      const names = ["kv", "messages", "blobs"];
      if (!names.every(name => db.objectStoreNames.contains(name)) || Array.from(db.objectStoreNames).some(name => !names.includes(name))) {
        throw Error("This browser has an unsupported DirectChat storage format.");
      }
      const snapshot = {};
      for (const name of names) {
        const transaction = db.transaction(name, "readonly");
        const store = transaction.objectStore(name);
        const keys = await request(store.getAllKeys());
        const values = await request(store.getAll());
        await done(transaction);
        snapshot[name] = {
          keys,
          values: await Promise.all(values.map(async value => value instanceof Blob
            ? { blob: true, type: value.type, bytes: b64(new Uint8Array(await value.arrayBuffer())) }
            : value))
        };
      }
      db.close();
      const state = snapshot.kv.values[snapshot.kv.keys.indexOf("state")];
      if (!state?.identity?.userID || !state.accounts?.some(account => account.id === state.identity.userID)) {
        throw Error("No transferable DirectChat account was found in this browser.");
      }
      const plain = enc.encode(JSON.stringify(snapshot));
      const keyBytes = random(32);
      const nonce = random(12);
      const secret = b64(random(32));
      const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
      const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
      status.textContent = "Moving your encrypted account…";
      const response = await fetch(`${config.targetOrigin}/api/legacy-migration/exchanges`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secretHash: await sha(secret),
          payload: { nonceBase64: b64(nonce), ciphertextBase64: b64(cipher), sourceDigest: await sha(plain) }
        })
      });
      if (!response.ok) throw Error("The secure service could not accept this move. Please try again.");
      const receipt = await response.json();
      location.replace(`${receipt.target}#receipt=${encodeURIComponent(`${receipt.token}.${secret}`)}.${b64(keyBytes)}`);
    } catch (error) {
      button.disabled = false;
      status.textContent = error instanceof Error ? error.message : "The move could not be completed. Please try again.";
    }
  };
}

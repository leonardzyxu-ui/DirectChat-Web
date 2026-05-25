import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Redis } from "@upstash/redis";
import { WebSocket, WebSocketServer } from "ws";

const MAX_MAILBOX_ITEMS = 100;
const MAX_QUEUED_ENVELOPE_BYTES = 64 * 1024;
const MAX_PUSH_SUBSCRIPTIONS = 10;
const PUSH_THROTTLE_MS = 20_000;
const PUSH_TTL_SECONDS = 60;
const MAX_ACCOUNT_VAULT_BYTES = 256 * 1024;
const ACCOUNT_IDLE_DELETE_MS = 72 * 60 * 60 * 1000;
const USER_INDEX_KEY = "directchat:users";
const CURRENT_FILE = fileURLToPath(import.meta.url);
const STATIC_ROOT = process.env.DIRECTCHAT_STATIC_ROOT
  ? path.resolve(process.cwd(), process.env.DIRECTCHAT_STATIC_ROOT)
  : path.resolve(path.dirname(CURRENT_FILE), "../web/dist");

export function createDirectChatServer(options = {}) {
  const store = options.store || createStoreFromEnv();
  const socketsByUser = new Map();
  const socketUsers = new Map();
  const wss = new WebSocketServer({ noServer: true });

  const server = createServer(async (request, response) => {
    try {
      await handleHTTP(request, response, { store, socketsByUser, socketUsers });
    } catch (error) {
      sendJSON(response, { error: error?.message || "internal server error" }, 500);
    }
  });

  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url || "/", publicBaseURL(request));
    const userID = cleanID(url.pathname.startsWith("/ws/") ? url.pathname.slice("/ws/".length) : "");
    if (!userID) {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }
    wss.handleUpgrade(request, socket, head, websocket => {
      attachSocket(websocket, userID, { store, socketsByUser, socketUsers });
    });
  });

  return { server, store };
}

async function handleHTTP(request, response, context) {
  const url = new URL(request.url || "/", publicBaseURL(request));

  if (request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders());
    response.end();
    return;
  }

  if (url.pathname === "/health") {
    sendJSON(response, { ok: true, service: "directchat-relay", runtime: "render-upstash" });
    return;
  }

  if (url.pathname === "/api/push/vapid-public-key") {
    sendJSON(response, {
      publicKey: process.env.VAPID_PUBLIC_KEY || "",
      enabled: Boolean(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY)
    });
    return;
  }

  if (url.pathname.startsWith("/api/accounts/")) {
    await handleAccountHTTP(request, response, url, context);
    return;
  }

  if (url.pathname.startsWith("/identity/")) {
    const userID = cleanID(url.pathname.slice("/identity/".length));
    if (!userID) {
      sendJSON(response, { error: "missing user id" }, 400);
      return;
    }
    await expireIdleAccountIfNeeded(userID, context);
    const record = await context.store.getUser(userID);
    if (!record.profile) {
      sendJSON(response, { error: "unknown user" }, 404);
      return;
    }
    sendJSON(response, {
      userID: record.profile.userID,
      publicKeyBase64: record.profile.publicKeyBase64,
      updatedAt: record.profile.updatedAt
    });
    return;
  }

  if (url.pathname.startsWith("/ws/")) {
    sendJSON(response, { error: "expected websocket" }, 426);
    return;
  }

  await serveStatic(response, url.pathname);
}

async function handleAccountHTTP(request, response, url, context) {
  const parts = url.pathname.split("/").filter(Boolean);
  const userID = cleanID(parts[2]);
  const action = parts[3] || "";
  if (!userID) {
    sendJSON(response, { error: "missing account id" }, 400);
    return;
  }
  if (!["challenge", "login", "vault"].includes(action)) {
    sendJSON(response, { error: "unknown account endpoint" }, 404);
    return;
  }

  await expireIdleAccountIfNeeded(userID, context);
  if (action === "challenge") {
    const record = await context.store.getUser(userID);
    if (!record.accountVault) {
      sendJSON(response, { error: "unknown account" }, 404);
      return;
    }
    sendJSON(response, {
      userID: record.accountVault.userID,
      exists: true,
      kdf: record.accountVault.kdf,
      updatedAt: record.accountVault.updatedAt
    });
    return;
  }

  const body = await readJSONBody(request);
  if (action === "login") {
    const record = await context.store.getUser(userID);
    if (!record.accountVault) {
      sendJSON(response, { error: "unknown account" }, 404);
      return;
    }
    if (!constantTimeEqual(String(body?.authVerifierBase64 || ""), record.accountVault.authVerifierBase64)) {
      sendJSON(response, { error: "invalid account safety code" }, 403);
      return;
    }
    await touchOfflineAccountActivity(userID, context);
    sendJSON(response, {
      userID: record.accountVault.userID,
      publicKeyBase64: record.accountVault.publicKeyBase64,
      kdf: record.accountVault.kdf,
      vault: record.accountVault.vault,
      updatedAt: record.accountVault.updatedAt
    });
    return;
  }

  const record = await context.store.getUser(userID);
  const account = validateAccountVault(body);
  if (record.accountVault && !constantTimeEqual(record.accountVault.authVerifierBase64, account.authVerifierBase64)) {
    sendJSON(response, { error: "invalid account safety code" }, 403);
    return;
  }

  const now = new Date().toISOString();
  record.accountVault = {
    ...account,
    createdAt: record.accountVault?.createdAt || now,
    updatedAt: now
  };
  record.profile = {
    userID: account.userID,
    publicKeyBase64: account.publicKeyBase64,
    updatedAt: now
  };
  await context.store.setUser(userID, record);
  await touchOfflineAccountActivity(userID, context);
  sendJSON(response, { ok: true, userID: account.userID, updatedAt: now });
}

function attachSocket(socket, urlUserID, context) {
  socket.on("message", data => {
    handleSocketMessage(socket, urlUserID, data, context).catch(error => {
      safeSend(socket, { type: "error", message: error?.message || String(error) });
    });
  });

  socket.on("close", () => {
    handleSocketClosed(socket, context).catch(() => {});
  });

  socket.on("error", () => {
    handleSocketClosed(socket, context).catch(() => {});
  });
}

async function handleSocketMessage(socket, urlUserID, data, context) {
  const message = JSON.parse(String(data));
  switch (message.type) {
    case "hello":
      if (message.userID !== urlUserID) {
        throw new Error("websocket user id mismatch");
      }
      await registerProfile(message, context);
      await markSocketOnline(socket, message.userID, context);
      safeSend(socket, { type: "ready", userID: message.userID });
      await flushMailbox(socket, message.userID, context);
      break;
    case "send":
      await forwardEnvelope(socket, message.envelope, Boolean(message.transient), context);
      break;
    case "pushSubscribe":
      await savePushSubscription(urlUserID, message.subscription, context);
      safeSend(socket, { type: "pushSubscribed" });
      break;
    case "pushUnsubscribe":
      await removePushSubscription(urlUserID, message.subscription?.endpoint || message.endpoint, context);
      safeSend(socket, { type: "pushUnsubscribed" });
      break;
    case "ping":
      safeSend(socket, { type: "pong", at: new Date().toISOString() });
      break;
    default:
      safeSend(socket, { type: "error", message: "unknown message type" });
  }
}

async function registerProfile(message, context) {
  const userID = cleanID(message.userID);
  if (!userID || userID !== message.userID) {
    throw new Error("invalid user id");
  }
  if (!message.publicKeyBase64 || message.publicKeyBase64.length > 2048) {
    throw new Error("missing public key");
  }

  const record = await context.store.getUser(userID);
  record.profile = {
    userID,
    publicKeyBase64: message.publicKeyBase64,
    updatedAt: new Date().toISOString()
  };
  await context.store.setUser(userID, record);
}

async function forwardEnvelope(socket, envelope, transient, context) {
  validateEnvelope(envelope);
  const result = await deliver(envelope, transient, context);
  safeSend(socket, {
    type: "sent",
    id: envelope.id,
    to: envelope.to,
    delivered: Boolean(result.delivered),
    queued: Boolean(result.queued),
    dropped: Boolean(result.dropped),
    reason: result.reason || null
  });
}

async function deliver(envelope, transient, context) {
  validateEnvelope(envelope);
  await expireIdleAccountIfNeeded(envelope.to, context);
  const recipientSockets = [...(context.socketsByUser.get(envelope.to) || [])];

  let delivered = false;
  for (const socket of recipientSockets) {
    if (safeSend(socket, { type: "envelope", envelope })) {
      delivered = true;
    } else {
      await handleSocketClosed(socket, context);
    }
  }

  if (delivered) {
    return { delivered: true, queued: false };
  }

  if (transient) {
    return { delivered: false, queued: false, dropped: true, reason: "recipient offline" };
  }

  const size = JSON.stringify(envelope).length;
  if (size > MAX_QUEUED_ENVELOPE_BYTES) {
    return { delivered: false, queued: false, dropped: true, reason: "envelope too large for offline queue" };
  }

  const record = await context.store.getUser(envelope.to);
  record.mailbox.push(envelope);
  while (record.mailbox.length > MAX_MAILBOX_ITEMS) {
    record.mailbox.shift();
  }
  await context.store.setUser(envelope.to, record);
  const pushNotified = await sendGenericPushes(envelope.to, context);
  return { delivered: false, queued: true, pushNotified };
}

async function flushMailbox(socket, userID, context) {
  const record = await context.store.getUser(userID);
  if (record.mailbox.length === 0) {
    return;
  }

  for (const envelope of record.mailbox) {
    safeSend(socket, { type: "envelope", envelope });
  }
  record.mailbox = [];
  await context.store.setUser(userID, record);
}

async function savePushSubscription(userID, subscription, context) {
  const normalized = normalizePushSubscription(subscription);
  const record = await context.store.getUser(userID);
  const subscriptions = record.pushSubscriptions.filter(item => item.endpoint !== normalized.endpoint);
  subscriptions.push(normalized);
  while (subscriptions.length > MAX_PUSH_SUBSCRIPTIONS) {
    subscriptions.shift();
  }
  record.pushSubscriptions = subscriptions;
  await context.store.setUser(userID, record);
}

async function removePushSubscription(userID, endpoint, context) {
  if (!endpoint) {
    return;
  }
  const record = await context.store.getUser(userID);
  record.pushSubscriptions = record.pushSubscriptions.filter(item => item.endpoint !== endpoint);
  await context.store.setUser(userID, record);
}

async function sendGenericPushes(userID, context) {
  if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) {
    return false;
  }

  const now = Date.now();
  const record = await context.store.getUser(userID);
  if (now - record.lastPushAt < PUSH_THROTTLE_MS) {
    return false;
  }
  if (record.pushSubscriptions.length === 0) {
    return false;
  }

  let sent = false;
  const retained = [];
  for (const subscription of record.pushSubscriptions) {
    const result = await sendWebPush(subscription);
    if (result.ok) {
      sent = true;
    }
    if (!result.remove) {
      retained.push(subscription);
    }
  }

  record.pushSubscriptions = retained;
  if (sent) {
    record.lastPushAt = now;
  }
  await context.store.setUser(userID, record);
  return sent;
}

async function markSocketOnline(socket, userID, context) {
  context.socketUsers.set(socket, userID);
  if (!context.socketsByUser.has(userID)) {
    context.socketsByUser.set(userID, new Set());
  }
  context.socketsByUser.get(userID).add(socket);

  const record = await context.store.getUser(userID);
  const now = new Date().toISOString();
  record.accountPresence = {
    userID,
    lastSeenAt: now,
    offlineSince: null,
    expiresAt: null
  };
  await context.store.setUser(userID, record);
}

async function handleSocketClosed(socket, context) {
  const userID = context.socketUsers.get(socket);
  context.socketUsers.delete(socket);
  if (!userID) {
    return;
  }
  const sockets = context.socketsByUser.get(userID);
  sockets?.delete(socket);
  if (sockets && sockets.size === 0) {
    context.socketsByUser.delete(userID);
    await markAccountOffline(userID, context);
  }
}

function activeSessionCount(userID, context) {
  return context.socketsByUser.get(userID)?.size || 0;
}

async function touchOfflineAccountActivity(userID, context) {
  if (activeSessionCount(userID, context) > 0) {
    const record = await context.store.getUser(userID);
    const now = new Date().toISOString();
    record.accountPresence = { userID, lastSeenAt: now, offlineSince: null, expiresAt: null };
    await context.store.setUser(userID, record);
    return;
  }
  await markAccountOffline(userID, context);
}

async function markAccountOffline(userID, context) {
  const record = await context.store.getUser(userID);
  if (!storedUserID(record)) {
    return;
  }
  const now = Date.now();
  record.accountPresence = {
    userID,
    lastSeenAt: new Date(now).toISOString(),
    offlineSince: new Date(now).toISOString(),
    expiresAt: new Date(now + ACCOUNT_IDLE_DELETE_MS).toISOString()
  };
  await context.store.setUser(userID, record);
}

async function expireIdleAccountIfNeeded(userID, context) {
  if (activeSessionCount(userID, context) > 0) {
    return false;
  }

  const record = await context.store.getUser(userID);
  if (!storedUserID(record)) {
    return false;
  }

  if (!record.accountPresence?.expiresAt) {
    await markAccountOffline(userID, context);
    return false;
  }

  const expiresAt = Date.parse(record.accountPresence.expiresAt);
  if (!Number.isFinite(expiresAt)) {
    await markAccountOffline(userID, context);
    return false;
  }

  if (Date.now() < expiresAt) {
    return false;
  }

  await context.store.deleteUser(userID);
  return true;
}

function storedUserID(record) {
  return record.accountVault?.userID || record.profile?.userID || "";
}

function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") {
    throw new Error("missing envelope");
  }
  for (const key of ["id", "from", "to", "kind", "createdAt", "ciphertextBase64", "senderPublicKeyBase64"]) {
    if (typeof envelope[key] !== "string" || envelope[key].length === 0) {
      throw new Error(`invalid envelope.${key}`);
    }
  }
  if (!cleanID(envelope.from) || !cleanID(envelope.to)) {
    throw new Error("invalid routing id");
  }
}

function validateAccountVault(body) {
  if (!body || typeof body !== "object") {
    throw new Error("missing account vault");
  }
  const userID = cleanID(body.userID);
  if (!userID || userID !== body.userID) {
    throw new Error("invalid account id");
  }
  if (!body.publicKeyBase64 || typeof body.publicKeyBase64 !== "string" || body.publicKeyBase64.length > 2048) {
    throw new Error("invalid public key");
  }
  if (!body.authVerifierBase64 || typeof body.authVerifierBase64 !== "string" || body.authVerifierBase64.length > 512) {
    throw new Error("invalid auth verifier");
  }
  if (!body.kdf || typeof body.kdf !== "object") {
    throw new Error("invalid kdf metadata");
  }
  if (!body.kdf.authSaltBase64 || typeof body.kdf.authSaltBase64 !== "string" || body.kdf.authSaltBase64.length > 512) {
    throw new Error("invalid auth salt");
  }
  if (!body.kdf.vaultSaltBase64 || typeof body.kdf.vaultSaltBase64 !== "string" || body.kdf.vaultSaltBase64.length > 512) {
    throw new Error("invalid vault salt");
  }
  if (body.kdf.algorithm !== "PBKDF2-HMAC-SHA256" || body.kdf.iterations !== 250000) {
    throw new Error("unsupported kdf");
  }
  if (!body.vault || typeof body.vault !== "object") {
    throw new Error("invalid encrypted vault");
  }
  if (!body.vault.nonceBase64 || typeof body.vault.nonceBase64 !== "string" || body.vault.nonceBase64.length > 128) {
    throw new Error("invalid vault nonce");
  }
  if (!body.vault.ciphertextBase64 || typeof body.vault.ciphertextBase64 !== "string") {
    throw new Error("invalid vault ciphertext");
  }
  if (body.vault.ciphertextBase64.length > MAX_ACCOUNT_VAULT_BYTES) {
    throw new Error("account vault too large");
  }

  return {
    userID,
    publicKeyBase64: body.publicKeyBase64,
    authVerifierBase64: body.authVerifierBase64,
    kdf: {
      algorithm: body.kdf.algorithm,
      iterations: body.kdf.iterations,
      authSaltBase64: body.kdf.authSaltBase64,
      vaultSaltBase64: body.kdf.vaultSaltBase64
    },
    vault: {
      version: Number(body.vault.version || 1),
      nonceBase64: body.vault.nonceBase64,
      ciphertextBase64: body.vault.ciphertextBase64
    }
  };
}

function normalizePushSubscription(subscription) {
  if (!subscription || typeof subscription !== "object") {
    throw new Error("missing push subscription");
  }
  const endpoint = String(subscription.endpoint || "");
  const url = new URL(endpoint);
  if (url.protocol !== "https:" || endpoint.length > 2048) {
    throw new Error("invalid push endpoint");
  }
  const keys = subscription.keys && typeof subscription.keys === "object"
    ? {
        p256dh: String(subscription.keys.p256dh || "").slice(0, 512),
        auth: String(subscription.keys.auth || "").slice(0, 256)
      }
    : {};
  return {
    endpoint,
    expirationTime: typeof subscription.expirationTime === "number" ? subscription.expirationTime : null,
    keys,
    savedAt: new Date().toISOString()
  };
}

async function sendWebPush(subscription) {
  try {
    const endpointURL = new URL(subscription.endpoint);
    const token = await createVapidJWT(endpointURL.origin);
    const response = await fetch(subscription.endpoint, {
      method: "POST",
      headers: {
        Authorization: `vapid t=${token}, k=${process.env.VAPID_PUBLIC_KEY}`,
        TTL: String(PUSH_TTL_SECONDS),
        Urgency: "normal"
      }
    });

    return {
      ok: response.ok,
      remove: response.status === 404 || response.status === 410
    };
  } catch {
    return { ok: false, remove: false };
  }
}

async function createVapidJWT(audience) {
  const header = { typ: "JWT", alg: "ES256" };
  const claims = {
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
    sub: process.env.VAPID_SUBJECT || "mailto:directchat@example.com"
  };
  const input = `${base64URLEncodeJSON(header)}.${base64URLEncodeJSON(claims)}`;
  const key = await importVapidPrivateKey();
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(input)
  );
  return `${input}.${base64URLEncodeBytes(new Uint8Array(signature))}`;
}

async function importVapidPrivateKey() {
  const rawPublicKey = base64URLDecodeBytes(process.env.VAPID_PUBLIC_KEY);
  if (rawPublicKey.length !== 65 || rawPublicKey[0] !== 0x04) {
    throw new Error("invalid VAPID public key");
  }
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: base64URLEncodeBytes(rawPublicKey.slice(1, 33)),
    y: base64URLEncodeBytes(rawPublicKey.slice(33, 65)),
    d: process.env.VAPID_PRIVATE_KEY,
    ext: false,
    key_ops: ["sign"]
  };
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

async function serveStatic(response, requestPath) {
  const safePath = decodeURIComponent(requestPath).replace(/^\/+/, "");
  const resolved = path.resolve(STATIC_ROOT, safePath || "index.html");
  const target = resolved.startsWith(STATIC_ROOT) && existsSync(resolved) ? resolved : path.join(STATIC_ROOT, "index.html");
  try {
    const body = await readFile(target);
    response.writeHead(200, {
      "Content-Type": contentTypeFor(target),
      "Cache-Control": target.endsWith("index.html") ? "no-store" : "public, max-age=31536000, immutable"
    });
    response.end(body);
  } catch {
    sendJSON(response, { ok: true, endpoints: ["/health", "/identity/<directchat-id>", "/ws/<directchat-id>"] });
  }
}

function contentTypeFor(filePath) {
  if (filePath.endsWith(".html")) return "text/html; charset=utf-8";
  if (filePath.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (filePath.endsWith(".css")) return "text/css; charset=utf-8";
  if (filePath.endsWith(".json") || filePath.endsWith(".webmanifest")) return "application/json; charset=utf-8";
  if (filePath.endsWith(".svg")) return "image/svg+xml";
  return "application/octet-stream";
}

function createStoreFromEnv() {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    return new UpstashStore(Redis.fromEnv());
  }
  console.warn("UPSTASH_REDIS_REST_URL/TOKEN are not set. Using in-memory storage.");
  return new MemoryStore();
}

class UpstashStore {
  constructor(redis) {
    this.redis = redis;
  }

  async getUser(userID) {
    const raw = await this.redis.get(userKey(userID));
    return normalizeRecord(raw);
  }

  async setUser(userID, record) {
    await this.redis.set(userKey(userID), JSON.stringify(normalizeRecord(record)));
    await this.redis.sadd(USER_INDEX_KEY, userID);
  }

  async deleteUser(userID) {
    await this.redis.del(userKey(userID));
    await this.redis.srem(USER_INDEX_KEY, userID);
  }
}

class MemoryStore {
  constructor() {
    this.users = new Map();
  }

  async getUser(userID) {
    return normalizeRecord(this.users.get(userID));
  }

  async setUser(userID, record) {
    this.users.set(userID, JSON.stringify(normalizeRecord(record)));
  }

  async deleteUser(userID) {
    this.users.delete(userID);
  }
}

function normalizeRecord(raw) {
  let value = raw;
  if (typeof raw === "string" && raw.trim()) {
    try {
      value = JSON.parse(raw);
    } catch {
      value = {};
    }
  }
  if (!value || typeof value !== "object") {
    value = {};
  }
  return {
    profile: value.profile || null,
    accountVault: value.accountVault || null,
    mailbox: Array.isArray(value.mailbox) ? value.mailbox : [],
    pushSubscriptions: Array.isArray(value.pushSubscriptions) ? value.pushSubscriptions : [],
    lastPushAt: Number(value.lastPushAt || 0),
    accountPresence: value.accountPresence || null
  };
}

function userKey(userID) {
  return `directchat:user:${userID}`;
}

async function readJSONBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1024 * 1024) {
      throw new Error("request body too large");
    }
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

function publicBaseURL(request) {
  const proto = request.headers["x-forwarded-proto"] || "http";
  const host = request.headers.host || `127.0.0.1:${process.env.PORT || 8787}`;
  return `${proto}://${host}`;
}

function sendJSON(response, value, status = 200) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...corsHeaders()
  });
  response.end(JSON.stringify(value));
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

function cleanID(value) {
  const trimmed = String(value || "").trim().toUpperCase();
  return /^[A-Z0-9-]{6,40}$/.test(trimmed) ? trimmed : "";
}

function safeSend(socket, value) {
  try {
    if (socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    socket.send(JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

function constantTimeEqual(left, right) {
  const leftValue = String(left || "");
  const rightValue = String(right || "");
  const maxLength = Math.max(leftValue.length, rightValue.length);
  let diff = leftValue.length ^ rightValue.length;
  for (let index = 0; index < maxLength; index += 1) {
    diff |= (leftValue.charCodeAt(index) || 0) ^ (rightValue.charCodeAt(index) || 0);
  }
  return diff === 0;
}

function base64URLEncodeJSON(value) {
  return base64URLEncodeBytes(new TextEncoder().encode(JSON.stringify(value)));
}

function base64URLEncodeBytes(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64URLDecodeBytes(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

if (process.argv[1] && path.resolve(process.argv[1]) === CURRENT_FILE) {
  const port = Number(process.env.PORT || 8787);
  const { server } = createDirectChatServer();
  server.listen(port, () => {
    console.log(`DirectChat Render relay listening on http://127.0.0.1:${port}`);
  });
}

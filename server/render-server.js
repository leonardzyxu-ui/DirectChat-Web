import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Redis } from "@upstash/redis";
import { WebSocket, WebSocketServer } from "ws";

const MIN_CLIENT_PROTOCOL_VERSION = 2;
const CLIENT_PROTOCOL_HEADER = "X-DirectChat-Protocol";
const SERVER_BUILD = "display-name-v5";
const MAX_MAILBOX_ITEMS = 100;
const MAX_DEVICE_MAILBOX_ITEMS = 100;
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
  const socketDevices = new Map();
  const wss = new WebSocketServer({ noServer: true });

  const server = createServer(async (request, response) => {
    try {
      await handleHTTP(request, response, { store, socketsByUser, socketUsers, socketDevices });
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
      attachSocket(websocket, userID, { store, socketsByUser, socketUsers, socketDevices });
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
    sendJSON(response, {
      ok: true,
      service: "directchat-relay",
      runtime: "render-upstash",
      syncProtocol: "privacy-gated-v2",
      minClientProtocolVersion: MIN_CLIENT_PROTOCOL_VERSION,
      serverBuild: SERVER_BUILD
    });
    return;
  }

  if (url.pathname === "/api/push/vapid-public-key") {
    sendJSON(response, {
      publicKey: process.env.VAPID_PUBLIC_KEY || "",
      enabled: Boolean(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY)
    });
    return;
  }

  if (url.pathname === "/admin") {
    serveAdminDashboard(response);
    return;
  }

  if (url.pathname === "/api/admin/overview") {
    if (!requireAdmin(request, response)) {
      return;
    }
    sendJSON(response, await collectAdminOverview(context));
    return;
  }

  if (url.pathname.startsWith("/api/accounts/")) {
    if (!requireSupportedClientProtocol(request, response)) {
      return;
    }
    await handleAccountHTTP(request, response, url, context);
    return;
  }

  if (url.pathname.startsWith("/identity/")) {
    if (!requireSupportedClientProtocol(request, response)) {
      return;
    }
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
  if (!["challenge", "login", "vault", "display-name"].includes(action)) {
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
  if (action === "display-name") {
    if (!record.accountVault) {
      sendJSON(response, { error: "unknown account" }, 404);
      return;
    }
    if (!constantTimeEqual(String(body?.authVerifierBase64 || ""), record.accountVault.authVerifierBase64)) {
      sendJSON(response, { error: "invalid account safety code" }, 403);
      return;
    }
    const displayName = sanitizeDisplayName(body?.displayName);
    if (!displayName) {
      sendJSON(response, { error: "invalid display name" }, 400);
      return;
    }
    const now = new Date().toISOString();
    record.accountVault = {
      ...record.accountVault,
      displayName,
      updatedAt: now
    };
    record.profile = {
      userID: record.accountVault.userID,
      displayName: bestProfileDisplayName(displayName, record),
      publicKeyBase64: record.accountVault.publicKeyBase64,
      updatedAt: now
    };
    await context.store.setUser(userID, record);
    await touchOfflineAccountActivity(userID, context);
    sendJSON(response, { ok: true, userID: record.accountVault.userID, displayName: record.profile.displayName, updatedAt: now });
    return;
  }

  const account = validateAccountVault(body);
  assertPublicKeyMatchesUserID(account.userID, account.publicKeyBase64);
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
    displayName: bestProfileDisplayName(account.displayName, record),
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
  if (message.type !== "hello" && message.type !== "ping" && !context.socketUsers.has(socket)) {
    safeSend(socket, unsupportedClientMessage("Complete a supported DirectChat handshake before using the relay."));
    closeSocket(socket);
    return;
  }
  switch (message.type) {
    case "hello":
      if (message.userID !== urlUserID) {
        throw new Error("websocket user id mismatch");
      }
      if (!isSupportedClientProtocol(message.protocolVersion)) {
        safeSend(socket, unsupportedClientMessage());
        closeSocket(socket);
        return;
      }
      await registerProfile(message, context);
      await registerDevice(message, context);
      await markSocketOnline(socket, message.userID, context, message.deviceID);
      const record = await context.store.getUser(message.userID);
      safeSend(socket, {
        type: "ready",
        userID: message.userID,
        deviceID: cleanDeviceID(message.deviceID) || null,
        devices: record.accountDevices
      });
      await flushMailbox(socket, message.userID, context);
      await broadcastSyncRequest(socket, message, context);
      break;
    case "send":
      await forwardEnvelope(socket, message.envelope, Boolean(message.transient), context, message.targetDeviceID);
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
  assertPublicKeyMatchesUserID(userID, message.publicKeyBase64);

  const record = await context.store.getUser(userID);
  record.profile = {
    userID,
    displayName: bestProfileDisplayName(message.displayName, record),
    publicKeyBase64: message.publicKeyBase64,
    updatedAt: new Date().toISOString()
  };
  await context.store.setUser(userID, record);
}

async function registerDevice(message, context) {
  const userID = cleanID(message.userID);
  const deviceID = cleanDeviceID(message.deviceID);
  if (!userID || !deviceID) {
    return;
  }
  const now = new Date().toISOString();
  const record = await context.store.getUser(userID);
  const existing = record.accountDevices.find(device => device.deviceID === deviceID);
  record.accountDevices = record.accountDevices.filter(device => device.deviceID !== deviceID);
  record.accountDevices.push({
    deviceID,
    userID,
    deviceName: sanitizeDeviceName(message.deviceName),
    createdAt: existing?.createdAt || now,
    lastSeenAt: now
  });
  while (record.accountDevices.length > 16) {
    record.accountDevices.shift();
  }
  await context.store.setUser(userID, record);
}

async function broadcastSyncRequest(socket, message, context) {
  const requesterDeviceID = cleanDeviceID(message.deviceID);
  if (!requesterDeviceID) {
    return;
  }
  const cursor = normalizeSyncCursor(message.syncCursor);
  const peers = [...(context.socketsByUser.get(message.userID) || [])];
  for (const peer of peers) {
    if (peer === socket) {
      continue;
    }
    const peerDeviceID = context.socketDevices.get(peer) || "";
    if (!peerDeviceID || peerDeviceID === requesterDeviceID) {
      continue;
    }
    safeSend(peer, {
      type: "syncRequest",
      requesterDeviceID,
      cursor
    });
  }
}

async function forwardEnvelope(socket, envelope, transient, context, targetDeviceID) {
  validateEnvelope(envelope);
  const socketUserID = context.socketUsers.get(socket);
  if (!socketUserID || envelope.from !== socketUserID) {
    throw new Error("sender mismatch");
  }
  const envelopeBytes = byteLengthJSON(envelope);
  await noteUserUsage(envelope.from, context, {
    outboundEnvelopes: 1,
    outboundBytes: envelopeBytes
  });
  const result = await deliver(envelope, transient, context, {
    sourceDeviceID: context.socketDevices.get(socket) || "",
    targetDeviceID
  });
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

async function deliver(envelope, transient, context, routing = {}) {
  validateEnvelope(envelope);
  const envelopeBytes = byteLengthJSON(envelope);
  await expireIdleAccountIfNeeded(envelope.to, context);
  const recipientSockets = [...(context.socketsByUser.get(envelope.to) || [])];
  const sourceDeviceID = cleanDeviceID(routing.sourceDeviceID);
  const targetDeviceID = cleanDeviceID(routing.targetDeviceID);

  let delivered = false;
  const deliveredDeviceIDs = new Set();
  for (const socket of recipientSockets) {
    const deviceID = context.socketDevices.get(socket) || "";
    if (targetDeviceID && deviceID !== targetDeviceID) {
      continue;
    }
    if (sourceDeviceID && deviceID === sourceDeviceID) {
      continue;
    }
    if (safeSend(socket, { type: "envelope", envelope })) {
      delivered = true;
      if (deviceID) {
        deliveredDeviceIDs.add(deviceID);
      }
    } else {
      await handleSocketClosed(socket, context);
    }
  }

  const record = await context.store.getUser(envelope.to);
  record.usageStats = mergeUsageStats(record.usageStats, {
    inboundEnvelopes: 1,
    inboundBytes: envelopeBytes
  });
  if (record.accountDevices.length > 0 && !transient) {
    const queued = await queueForMissingDevices(envelope, record, deliveredDeviceIDs, sourceDeviceID, targetDeviceID, context);
    record.usageStats = mergeUsageStats(record.usageStats, {
      deliveredLive: delivered ? 1 : 0,
      queuedEnvelopes: queued ? 1 : 0
    });
    if (delivered || queued) {
      await context.store.setUser(envelope.to, record);
      return { delivered, queued };
    }
  }

  if (delivered) {
    record.usageStats = mergeUsageStats(record.usageStats, { deliveredLive: 1 });
    await context.store.setUser(envelope.to, record);
    return { delivered: true, queued: false };
  }

  if (transient) {
    record.usageStats = mergeUsageStats(record.usageStats, { droppedEnvelopes: 1 });
    await context.store.setUser(envelope.to, record);
    return { delivered: false, queued: false, dropped: true, reason: "recipient offline" };
  }

  if (envelopeBytes > MAX_QUEUED_ENVELOPE_BYTES) {
    record.usageStats = mergeUsageStats(record.usageStats, { droppedEnvelopes: 1 });
    await context.store.setUser(envelope.to, record);
    return { delivered: false, queued: false, dropped: true, reason: "envelope too large for offline queue" };
  }

  record.mailbox.push(envelope);
  record.usageStats = mergeUsageStats(record.usageStats, { queuedEnvelopes: 1 });
  while (record.mailbox.length > MAX_MAILBOX_ITEMS) {
    record.mailbox.shift();
  }
  await context.store.setUser(envelope.to, record);
  const pushNotified = await sendGenericPushes(envelope.to, context);
  return { delivered: false, queued: true, pushNotified };
}

async function flushMailbox(socket, userID, context) {
  const record = await context.store.getUser(userID);
  const deviceID = context.socketDevices.get(socket) || "";
  if (deviceID) {
    const mailbox = Array.isArray(record.deviceMailboxes[deviceID]) ? record.deviceMailboxes[deviceID] : [];
    for (const envelope of mailbox) {
      safeSend(socket, { type: "envelope", envelope });
    }
    delete record.deviceMailboxes[deviceID];
  }

  if (record.mailbox.length === 0) {
    await context.store.setUser(userID, record);
    return;
  }

  for (const envelope of record.mailbox) {
    safeSend(socket, { type: "envelope", envelope });
  }
  record.mailbox = [];
  await context.store.setUser(userID, record);
}

async function queueForMissingDevices(envelope, record, deliveredDeviceIDs, sourceDeviceID, targetDeviceID, context) {
  const size = JSON.stringify(envelope).length;
  if (size > MAX_QUEUED_ENVELOPE_BYTES) {
    return false;
  }
  const recipients = record.accountDevices.filter(device => {
    if (!device.deviceID) {
      return false;
    }
    if (targetDeviceID) {
      return device.deviceID === targetDeviceID;
    }
    return device.deviceID !== sourceDeviceID;
  });
  const missing = recipients.filter(device => !deliveredDeviceIDs.has(device.deviceID));
  if (missing.length === 0) {
    return false;
  }
  for (const device of missing) {
    const mailbox = Array.isArray(record.deviceMailboxes[device.deviceID]) ? record.deviceMailboxes[device.deviceID] : [];
    mailbox.push(envelope);
    while (mailbox.length > MAX_DEVICE_MAILBOX_ITEMS) {
      mailbox.shift();
    }
    record.deviceMailboxes[device.deviceID] = mailbox;
  }
  await context.store.setUser(envelope.to, record);
  await sendGenericPushes(envelope.to, context);
  return true;
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

async function markSocketOnline(socket, userID, context, deviceID) {
  context.socketUsers.set(socket, userID);
  const cleanDevice = cleanDeviceID(deviceID);
  if (cleanDevice) {
    context.socketDevices.set(socket, cleanDevice);
  }
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
  context.socketDevices.delete(socket);
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

async function noteUserUsage(userID, context, patch) {
  const record = await context.store.getUser(userID);
  if (!storedUserID(record) && !record.profile) {
    return;
  }
  record.usageStats = mergeUsageStats(record.usageStats, patch);
  await context.store.setUser(userID, record);
}

function mergeUsageStats(existing, patch) {
  const current = normalizeUsageStats(existing);
  const now = new Date().toISOString();
  return {
    ...current,
    outboundEnvelopes: current.outboundEnvelopes + Number(patch.outboundEnvelopes || 0),
    outboundBytes: current.outboundBytes + Number(patch.outboundBytes || 0),
    inboundEnvelopes: current.inboundEnvelopes + Number(patch.inboundEnvelopes || 0),
    inboundBytes: current.inboundBytes + Number(patch.inboundBytes || 0),
    queuedEnvelopes: current.queuedEnvelopes + Number(patch.queuedEnvelopes || 0),
    droppedEnvelopes: current.droppedEnvelopes + Number(patch.droppedEnvelopes || 0),
    deliveredLive: current.deliveredLive + Number(patch.deliveredLive || 0),
    firstSeenAt: current.firstSeenAt || now,
    updatedAt: now
  };
}

function normalizeUsageStats(value) {
  const stats = value && typeof value === "object" ? value : {};
  return {
    outboundEnvelopes: safeNumber(stats.outboundEnvelopes),
    outboundBytes: safeNumber(stats.outboundBytes),
    inboundEnvelopes: safeNumber(stats.inboundEnvelopes),
    inboundBytes: safeNumber(stats.inboundBytes),
    queuedEnvelopes: safeNumber(stats.queuedEnvelopes),
    droppedEnvelopes: safeNumber(stats.droppedEnvelopes),
    deliveredLive: safeNumber(stats.deliveredLive),
    firstSeenAt: typeof stats.firstSeenAt === "string" ? stats.firstSeenAt : null,
    updatedAt: typeof stats.updatedAt === "string" ? stats.updatedAt : null
  };
}

async function collectAdminOverview(context) {
  const userIDs = typeof context.store.listUserIDs === "function" ? await context.store.listUserIDs() : [];
  const users = [];
  for (const userID of userIDs.map(cleanID).filter(Boolean).sort()) {
    const record = await context.store.getUser(userID);
    if (!storedUserID(record)) {
      continue;
    }
    const queued = queuedEnvelopeStats(record);
    const nameInfo = dashboardDisplayNameInfo(record);
    const storageBytes = byteLengthJSON(record);
    users.push({
      userID,
      displayName: nameInfo.displayName,
      displayNameSource: nameInfo.source,
      onlineSessions: activeSessionCount(userID, context),
      devices: record.accountDevices.map(device => ({
        deviceID: device.deviceID,
        deviceName: device.deviceName || "DirectChat device",
        lastSeenAt: device.lastSeenAt || null
      })),
      hasAccountVault: Boolean(record.accountVault),
      queuedEnvelopeCount: queued.count,
      queuedBytes: queued.bytes,
      storageBytes,
      pushSubscriptions: record.pushSubscriptions.length,
      presence: record.accountPresence,
      usage: normalizeUsageStats(record.usageStats)
    });
  }
  return {
    generatedAt: new Date().toISOString(),
    runtime: "render-upstash",
    serverBuild: SERVER_BUILD,
    users,
    totals: users.reduce((totals, user) => ({
      users: totals.users + 1,
      onlineSessions: totals.onlineSessions + user.onlineSessions,
      devices: totals.devices + user.devices.length,
      queuedEnvelopeCount: totals.queuedEnvelopeCount + user.queuedEnvelopeCount,
      queuedBytes: totals.queuedBytes + user.queuedBytes,
      storageBytes: totals.storageBytes + user.storageBytes,
      inboundBytes: totals.inboundBytes + user.usage.inboundBytes,
      outboundBytes: totals.outboundBytes + user.usage.outboundBytes
    }), {
      users: 0,
      onlineSessions: 0,
      devices: 0,
      queuedEnvelopeCount: 0,
      queuedBytes: 0,
      storageBytes: 0,
      inboundBytes: 0,
      outboundBytes: 0
    }),
    privacy: "Dashboard shows relay metadata only. Account vaults, messages, file names, file bytes, private keys, and safety codes are not returned."
  };
}

function queuedEnvelopeStats(record) {
  const envelopes = [...record.mailbox];
  for (const mailbox of Object.values(record.deviceMailboxes)) {
    if (Array.isArray(mailbox)) {
      envelopes.push(...mailbox);
    }
  }
  return {
    count: envelopes.length,
    bytes: envelopes.reduce((sum, envelope) => sum + byteLengthJSON(envelope), 0)
  };
}

function requireAdmin(request, response) {
  const token = process.env.DIRECTCHAT_ADMIN_TOKEN || "";
  if (!token) {
    sendJSON(response, { error: "admin dashboard is not configured" }, 503);
    return false;
  }
  const authorization = String(request.headers.authorization || "");
  const candidate = authorization.toLowerCase().startsWith("bearer ")
    ? authorization.slice(7).trim()
    : String(request.headers["x-directchat-admin-token"] || "");
  if (!constantTimeEqual(candidate, token)) {
    sendJSON(response, { error: "unauthorized" }, 401);
    return false;
  }
  return true;
}

function requireSupportedClientProtocol(request, response) {
  if (isSupportedClientProtocol(request.headers[CLIENT_PROTOCOL_HEADER.toLowerCase()])) {
    return true;
  }
  sendJSON(response, unsupportedClientMessage(), 426);
  return false;
}

function isSupportedClientProtocol(value) {
  const version = Number.parseInt(String(value || ""), 10);
  return Number.isFinite(version) && version >= MIN_CLIENT_PROTOCOL_VERSION;
}

function unsupportedClientMessage(message = "Update DirectChat before using this relay.") {
  return {
    type: "error",
    code: "upgrade_required",
    error: "upgrade_required",
    message,
    minClientProtocolVersion: MIN_CLIENT_PROTOCOL_VERSION
  };
}

function closeSocket(socket) {
  try {
    socket.close(1008, "upgrade required");
  } catch {
    // Some runtimes throw if the socket is already closing.
  }
}

function assertPublicKeyMatchesUserID(userID, publicKeyBase64) {
  const expectedID = directChatIDForPublicKey(publicKeyBase64);
  if (expectedID !== userID) {
    throw new Error("public key does not match DirectChat ID");
  }
}

function directChatIDForPublicKey(publicKeyBase64) {
  const bytes = Buffer.from(String(publicKeyBase64 || ""), "base64");
  let compact;
  if (bytes.length === 65 && bytes[0] === 0x04) {
    compact = bytes.subarray(1);
  } else if (bytes.length === 64) {
    compact = bytes;
  } else {
    throw new Error("unsupported public key format");
  }
  return `DC-${createHash("sha256").update(compact).digest("hex").slice(0, 12).toUpperCase()}`;
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
    displayName: sanitizeDisplayName(body.displayName),
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
    let body = await readFile(target);
    if (target.endsWith(".js")) {
      body = Buffer.from(patchDirectChatWebBundle(body.toString("utf8")), "utf8");
    }
    response.writeHead(200, {
      "Content-Type": contentTypeFor(target),
      "Cache-Control": target.endsWith("index.html") ? "no-store" : "public, max-age=31536000, immutable"
    });
    response.end(body);
  } catch {
    sendJSON(response, { ok: true, endpoints: ["/health", "/identity/<directchat-id>", "/ws/<directchat-id>"] });
  }
}

function serveAdminDashboard(response) {
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store"
  });
  response.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DirectChat Admin</title>
  <style>
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7f9; color: #111827; }
    [hidden] { display: none !important; }
    body { margin: 0; min-height: 100vh; background: #f6f7f9; color: #111827; }
    header { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 20px clamp(16px, 4vw, 40px); border-bottom: 1px solid #e5e7eb; background: #fff; }
    h1 { margin: 0; font-size: clamp(22px, 3vw, 34px); letter-spacing: 0; }
    main { width: min(1180px, calc(100vw - 28px)); margin: 20px auto 40px; display: grid; gap: 16px; }
    .login, .panel, .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.05); }
    .login { display: grid; gap: 12px; max-width: 440px; margin: 12vh auto 0; padding: 18px; }
    .login input { height: 42px; padding: 0 12px; border: 1px solid #d1d5db; border-radius: 8px; font: inherit; }
    button { height: 38px; padding: 0 14px; border: 0; border-radius: 8px; background: #0f172a; color: #fff; font-weight: 750; cursor: pointer; }
    button.secondary { background: #e5e7eb; color: #111827; }
    .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .card { padding: 14px; }
    .card span { display: block; color: #6b7280; font-size: 12px; font-weight: 750; text-transform: uppercase; }
    .card strong { display: block; margin-top: 5px; font-size: 24px; }
    .panel { overflow: hidden; }
    .panel-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 14px 16px; border-bottom: 1px solid #e5e7eb; }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; min-width: 920px; }
    th, td { padding: 11px 12px; border-bottom: 1px solid #edf0f3; text-align: left; font-size: 13px; vertical-align: top; }
    th { color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 0; background: #fafafa; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .muted { color: #6b7280; }
    .ok { color: #047857; font-weight: 800; }
    .warn { color: #b45309; font-weight: 800; }
    .danger { color: #b91c1c; font-weight: 800; }
    .privacy { padding: 12px 14px; color: #4b5563; background: #eef6ff; border: 1px solid #bfdbfe; border-radius: 8px; font-size: 13px; }
    @media (max-width: 760px) { header { align-items: flex-start; flex-direction: column; } .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    @media (prefers-color-scheme: dark) {
      :root, body { background: #0b1020; color: #e5e7eb; }
      header, .login, .panel, .card { background: #111827; border-color: #263245; box-shadow: none; }
      th { background: #0f172a; color: #9ca3af; }
      th, td, .panel-head { border-color: #263245; }
      .login input { background: #0f172a; color: #e5e7eb; border-color: #374151; }
      button.secondary { background: #263245; color: #e5e7eb; }
      .muted { color: #9ca3af; }
      .privacy { background: #10243f; border-color: #1d4ed8; color: #bfdbfe; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>DirectChat Admin</h1>
      <div class="muted" id="subtitle">Relay metadata monitor</div>
    </div>
    <div>
      <button class="secondary" id="refresh">Refresh</button>
      <button class="secondary" id="logout">Lock</button>
    </div>
  </header>
  <main>
    <section class="login" id="login">
      <strong>Admin token required</strong>
      <span class="muted">Set DIRECTCHAT_ADMIN_TOKEN on Render. The token stays in this browser session.</span>
      <input id="token" type="password" autocomplete="current-password" placeholder="Admin token" />
      <button id="unlock">Open dashboard</button>
      <span class="danger" id="login-error"></span>
    </section>
    <section id="dashboard" hidden>
      <div class="privacy" id="privacy"></div>
      <div class="cards">
        <div class="card"><span>Users</span><strong id="total-users">0</strong></div>
        <div class="card"><span>Online sessions</span><strong id="total-online">0</strong></div>
        <div class="card"><span>Queued envelopes</span><strong id="total-queued">0</strong></div>
        <div class="card"><span>Storage estimate</span><strong id="total-storage">0 B</strong></div>
      </div>
      <div class="panel">
        <div class="panel-head">
          <strong>Users</strong>
          <span class="muted" id="generated-at"></span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Name Source</th><th>ID</th><th>Status</th><th>Devices</th><th>Queued</th><th>Traffic</th><th>Storage</th><th>Last Seen</th>
              </tr>
            </thead>
            <tbody id="users"></tbody>
          </table>
        </div>
      </div>
    </section>
  </main>
  <script>
    const tokenInput = document.getElementById("token");
    const login = document.getElementById("login");
    const dashboard = document.getElementById("dashboard");
    const loginError = document.getElementById("login-error");
    const stored = sessionStorage.getItem("directchat_admin_token");
    if (stored) {
      tokenInput.value = stored;
      loadDashboard();
    }
    document.getElementById("unlock").addEventListener("click", () => {
      sessionStorage.setItem("directchat_admin_token", tokenInput.value);
      loadDashboard();
    });
    document.getElementById("refresh").addEventListener("click", loadDashboard);
    document.getElementById("logout").addEventListener("click", () => {
      sessionStorage.removeItem("directchat_admin_token");
      dashboard.hidden = true;
      login.hidden = false;
      tokenInput.value = "";
    });
    async function loadDashboard() {
      const token = sessionStorage.getItem("directchat_admin_token") || tokenInput.value;
      loginError.textContent = "";
      const response = await fetch("/api/admin/overview", {
        headers: { Authorization: "Bearer " + token },
        cache: "no-store"
      });
      if (!response.ok) {
        login.hidden = false;
        dashboard.hidden = true;
        loginError.textContent = response.status === 503 ? "Set DIRECTCHAT_ADMIN_TOKEN on Render first." : "Token rejected.";
        return;
      }
      const data = await response.json();
      login.hidden = true;
      dashboard.hidden = false;
      document.getElementById("privacy").textContent = data.privacy;
      document.getElementById("generated-at").textContent = "Updated " + new Date(data.generatedAt).toLocaleString();
      document.getElementById("subtitle").textContent = data.runtime + " - " + (data.serverBuild || "unknown-build") + " - " + data.users.length + " users";
      document.getElementById("total-users").textContent = data.totals.users;
      document.getElementById("total-online").textContent = data.totals.onlineSessions;
      document.getElementById("total-queued").textContent = data.totals.queuedEnvelopeCount;
      document.getElementById("total-storage").textContent = formatBytes(data.totals.storageBytes);
      document.getElementById("users").innerHTML = data.users.map(user => {
        const traffic = formatBytes(user.usage.inboundBytes) + " in / " + formatBytes(user.usage.outboundBytes) + " out";
        const devices = user.devices.length ? user.devices.map(device => escapeHTML(device.deviceName)).join("<br>") : "<span class='muted'>none</span>";
        const statusClass = user.onlineSessions > 0 ? "ok" : user.queuedEnvelopeCount > 20 ? "warn" : "muted";
        const lastSeen = user.presence?.lastSeenAt ? new Date(user.presence.lastSeenAt).toLocaleString() : "unknown";
        return "<tr>" +
          "<td>" + escapeHTML(user.displayName || "(no name)") + "</td>" +
          "<td class='muted'>" + escapeHTML(user.displayNameSource || "none") + "</td>" +
          "<td><code>" + escapeHTML(user.userID) + "</code></td>" +
          "<td class='" + statusClass + "'>" + (user.onlineSessions > 0 ? "online" : "offline") + "</td>" +
          "<td>" + devices + "</td>" +
          "<td>" + user.queuedEnvelopeCount + " / " + formatBytes(user.queuedBytes) + "</td>" +
          "<td>" + traffic + "</td>" +
          "<td>" + formatBytes(user.storageBytes) + "</td>" +
          "<td>" + escapeHTML(lastSeen) + "</td>" +
        "</tr>";
      }).join("");
    }
    function formatBytes(value) {
      if (value < 1024) return value + " B";
      if (value < 1024 * 1024) return (value / 1024).toFixed(1) + " KB";
      return (value / 1024 / 1024).toFixed(1) + " MB";
    }
    function escapeHTML(value) {
      return String(value || "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
    }
  </script>
</body>
</html>`);
}

function patchDirectChatWebBundle(source) {
  return source
    .replace(
      "Message to ${O.to||\"recipient\"} is queued and still pending.",
      "Message sent to the relay. ${O.to||\"Recipient\"} will receive it when online."
    )
    .replace(
      'return i.dropped?"failed":i.delivered?"sent":"pending"',
      'return i.dropped?"failed":i.delivered||i.queued?"sent":"pending"'
    );
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

  async listUserIDs() {
    const values = await this.redis.smembers(USER_INDEX_KEY);
    return Array.isArray(values) ? values : [];
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

  async listUserIDs() {
    return [...this.users.keys()];
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
    accountDevices: Array.isArray(value.accountDevices) ? value.accountDevices.filter(device => cleanDeviceID(device?.deviceID)) : [],
    deviceMailboxes: value.deviceMailboxes && typeof value.deviceMailboxes === "object" ? value.deviceMailboxes : {},
    pushSubscriptions: Array.isArray(value.pushSubscriptions) ? value.pushSubscriptions : [],
    lastPushAt: Number(value.lastPushAt || 0),
    accountPresence: value.accountPresence || null,
    usageStats: normalizeUsageStats(value.usageStats)
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

function byteLengthJSON(value) {
  return Buffer.byteLength(JSON.stringify(value || null), "utf8");
}

function safeNumber(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) && number > 0 ? number : 0;
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
    "Access-Control-Allow-Headers": `Content-Type, ${CLIENT_PROTOCOL_HEADER}`
  };
}

function cleanID(value) {
  const trimmed = String(value || "").trim().toUpperCase();
  return /^[A-Z0-9-]{6,40}$/.test(trimmed) ? trimmed : "";
}

function cleanDeviceID(value) {
  const trimmed = String(value || "").trim();
  return /^[A-Za-z0-9:_-]{1,96}$/.test(trimmed) ? trimmed : "";
}

function sanitizeDeviceName(value) {
  const trimmed = String(value || "").trim();
  return trimmed ? trimmed.slice(0, 80) : "DirectChat device";
}

function sanitizeDisplayName(value) {
  const trimmed = String(value || "").trim();
  return trimmed ? trimmed.slice(0, 80) : "";
}

function dashboardDisplayName(record) {
  return dashboardDisplayNameInfo(record).displayName;
}

function dashboardDisplayNameInfo(record) {
  const profileName = sanitizeDisplayName(record.profile?.displayName);
  const accountName = sanitizeDisplayName(record.accountVault?.displayName);
  if (isUsefulDisplayName(profileName)) {
    return { displayName: profileName, source: "profile" };
  }
  if (isUsefulDisplayName(accountName)) {
    return { displayName: accountName, source: "account" };
  }
  if (profileName || accountName) {
    return { displayName: "", source: "generic" };
  }
  return { displayName: "", source: "none" };
}

function bestProfileDisplayName(incoming, record) {
  const incomingName = sanitizeDisplayName(incoming);
  const existingName = sanitizeDisplayName(record.profile?.displayName);
  const accountName = sanitizeDisplayName(record.accountVault?.displayName);
  if (isUsefulDisplayName(incomingName)) {
    return incomingName;
  }
  if (isUsefulDisplayName(existingName)) {
    return existingName;
  }
  if (isUsefulDisplayName(accountName)) {
    return accountName;
  }
  return incomingName || existingName || accountName || "";
}

function isUsefulDisplayName(value) {
  const normalized = sanitizeDisplayName(value).toLowerCase();
  return Boolean(normalized && normalized !== "me" && normalized !== "directchat");
}

function normalizeSyncCursor(value) {
  if (!value || typeof value !== "object") {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key, seq]) => cleanDeviceID(key) && typeof seq === "number" && Number.isFinite(seq) && seq >= 0)
      .map(([key, seq]) => [key, Math.floor(seq)])
  );
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

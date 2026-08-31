import test from "node:test";
import assert from "node:assert/strict";
import { legacyRedirectLocation } from "./legacy-redirect.mjs";
import { base64URLFromBytes, legacyDoorwayHTML, migrationConfig } from "./legacy-doorway.mjs";

test("legacy redirect preserves paths and queries on the pinned VPS host", () => {
  assert.equal(
    legacyRedirectLocation("https://directchat.srv1921833.hstgr.cloud/", "/settings?view=relay"),
    "https://directchat.srv1921833.hstgr.cloud/settings?view=relay"
  );
});

test("legacy redirect accepts only the pinned origin with an optional trailing slash", () => {
  for (const target of [
    "https://directchat.srv1921833.hstgr.cloud",
    "https://directchat.srv1921833.hstgr.cloud/"
  ]) {
    assert.equal(legacyRedirectLocation(target, "/"), "https://directchat.srv1921833.hstgr.cloud/");
  }
});

test("legacy redirect fails closed for every non-pinned configuration shape", () => {
  for (const target of [
    "",
    "http://directchat.srv1921833.hstgr.cloud",
    "https://directchat.srv1921833.hstgr.cloud.evil.test/",
    "https://sub.directchat.srv1921833.hstgr.cloud/",
    "https://directchat.srv1921833.hstgr.cloud:8443/",
    "https://user@directchat.srv1921833.hstgr.cloud/",
    "https://directchat.srv1921833.hstgr.cloud/other",
    "https://directchat.srv1921833.hstgr.cloud/?query=1",
    "https://directchat.srv1921833.hstgr.cloud/#fragment",
    "not a URL"
  ]) {
    assert.equal(legacyRedirectLocation(target, "/"), null, target);
  }
});

test("migration config upgrades the retired Boston target to Malaysia", () => {
  assert.deepEqual(
    migrationConfig({
      DIRECTCHAT_LEGACY_MIGRATION_ORIGIN: "https://directchat-relay.onrender.com",
      DIRECTCHAT_LEGACY_MIGRATION_TARGET: "https://directchat.srv1807979.hstgr.cloud/"
    }),
    {
      oldOrigin: "https://directchat-relay.onrender.com",
      targetOrigin: "https://directchat.srv1921833.hstgr.cloud"
    }
  );
});

test("migration base64 encoding handles large account snapshots without argument explosion", () => {
  const bytes = Uint8Array.from({ length: 512 * 1024 }, (_, index) => index % 256);
  assert.equal(base64URLFromBytes(bytes), Buffer.from(bytes).toString("base64url"));

  const html = legacyDoorwayHTML({
    oldOrigin: "https://directchat-relay.onrender.com",
    targetOrigin: "https://directchat.srv1921833.hstgr.cloud"
  });
  assert.match(html, /offset \+= 0x8000/);
  assert.doesNotMatch(html, /String\.fromCharCode\(\.\.\.b\)/);
});

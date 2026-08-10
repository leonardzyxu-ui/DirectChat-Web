import test from "node:test";
import assert from "node:assert/strict";
import { legacyRedirectLocation } from "./legacy-redirect.mjs";

test("legacy redirect preserves paths and queries on the pinned VPS host", () => {
  assert.equal(
    legacyRedirectLocation("https://directchat.srv1807979.hstgr.cloud/", "/settings?view=relay"),
    "https://directchat.srv1807979.hstgr.cloud/settings?view=relay"
  );
});

test("legacy redirect fails closed for missing, non-HTTPS, or malformed targets", () => {
  assert.equal(legacyRedirectLocation("", "/"), null);
  assert.equal(legacyRedirectLocation("http://example.test", "/"), null);
  assert.equal(legacyRedirectLocation("not a URL", "/"), null);
});

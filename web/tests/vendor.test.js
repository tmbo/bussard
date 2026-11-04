// The vendored jsQR (web/enroll/vendor/) is the file its record names:
// jsQR.json holds the npm version and the sha256 of dist/jsQR.js, and this
// test fails when the file changes without the record (#797).
// Run: node --test web/tests/

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const vendor = new URL("../enroll/vendor/", import.meta.url);

test("test_jsqr_matches_recorded_sha256", () => {
  const record = JSON.parse(readFileSync(new URL("jsQR.json", vendor), "utf8"));
  assert.equal(record.package, "jsqr");
  assert.match(record.version, /^\d+\.\d+\.\d+$/);
  assert.match(record.sha256, /^[0-9a-f]{64}$/);
  const bytes = readFileSync(new URL(record.file, vendor));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), record.sha256);
});

// The enrolment page's display logic: status wording, the summary, scan
// de-duplication, remembered choices and the keyboard inset.
// Run: node --test web/tests/

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  PREF_KEYS,
  SCAN_HOLD_MS,
  STATUS_WORDS,
  ScanGate,
  bottomInset,
  countStatuses,
  readPref,
  shortStatus,
  statusDetail,
  statusTone,
  summaryText,
  writePref,
} from "../enroll/ui.js";

test("test_shortStatus_words_from_issue_783", () => {
  assert.equal(shortStatus("stored"), "saved");
  assert.equal(shortStatus("unassigned"), "waiting for device");
  assert.equal(shortStatus("already_stored"), "already known");
  assert.equal(shortStatus("conflict"), "conflict");
  assert.equal(shortStatus("invalid"), "invalid");
  assert.equal(shortStatus("weird"), "weird");
});

test("test_shortStatus_unassigned_never_reads_as_done", () => {
  assert.notEqual(shortStatus("unassigned"), "saved");
  assert.equal(statusTone("unassigned"), "wait");
  assert.match(statusDetail({ status: "unassigned" }), /until a device in the model has this serial/);
});

test("test_statusTone_groups", () => {
  assert.equal(statusTone("stored"), "good");
  assert.equal(statusTone("already_stored"), "good");
  for (const s of ["conflict", "invalid", "error", "rejected"]) assert.equal(statusTone(s), "bad");
  for (const s of ["queued", "sending", "sent"]) assert.equal(statusTone(s), "pending");
});

test("test_statusDetail_saved_names_device", () => {
  assert.equal(statusDetail({ status: "stored", ia: "1.1.12", name: "Kitchen dimmer" }), "Saved for 1.1.12 Kitchen dimmer");
  assert.equal(statusDetail({ status: "stored", ia: "1.1.12" }), "Saved for 1.1.12");
  assert.equal(statusDetail({ status: "stored" }), STATUS_WORDS.stored.long);
});

test("test_statusDetail_appends_message", () => {
  assert.equal(
    statusDetail({ status: "rejected", message: "The relay's limit for this session is reached." }),
    "Not sent. The relay's limit for this session is reached.",
  );
});

test("test_countStatuses_groups", () => {
  assert.deepEqual(
    countStatuses(["stored", "stored", "unassigned", "already_stored", "conflict", "rejected", "sent", "queued"]),
    { total: 8, saved: 2, waiting: 1, known: 1, problems: 2, inFlight: 2 },
  );
});

test("test_summaryText_issue_example", () => {
  assert.equal(summaryText(["stored", "unassigned", "stored"]), "3 labels · 2 saved · 1 waiting for its device");
});

test("test_summaryText_empty_and_singular", () => {
  assert.equal(summaryText([]), "No labels yet");
  assert.equal(summaryText(["sending"]), "1 label · 1 sending");
  assert.equal(summaryText(["conflict"]), "1 label · 1 problem");
});

test("test_summaryText_all_groups", () => {
  assert.equal(
    summaryText(["stored", "unassigned", "unassigned", "already_stored", "invalid", "error", "sent"]),
    "7 labels · 1 saved · 2 waiting for their devices · 1 already known · 1 sending · 2 problems",
  );
});

test("test_ScanGate_new_then_hold_while_in_view", () => {
  const gate = new ScanGate(1000);
  assert.equal(gate.decide("a", false, 0), "new");
  // Still in view: frames every ~180 ms keep it held, however long.
  for (let t = 180; t < 5000; t += 180) assert.equal(gate.decide("a", true, t), "hold");
});

test("test_ScanGate_repeat_after_label_left_view", () => {
  const gate = new ScanGate(1000);
  assert.equal(gate.decide("a", false, 0), "new");
  assert.equal(gate.decide("a", true, 2000), "repeat");
  assert.equal(gate.decide("a", true, 2100), "hold");
});

test("test_ScanGate_keys_are_independent", () => {
  const gate = new ScanGate();
  assert.equal(gate.decide("a", false, 0), "new");
  assert.equal(gate.decide("b", false, 10), "new");
  assert.equal(gate.decide("a", true, SCAN_HOLD_MS + 1), "repeat");
});

test("test_ScanGate_seen_in_session_from_typing_is_repeat", () => {
  const gate = new ScanGate();
  assert.equal(gate.decide("typed", true, 0), "repeat");
});

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
}

const throwing = {
  getItem() {
    throw new Error("SecurityError");
  },
  setItem() {
    throw new Error("QuotaExceededError");
  },
};

test("test_readPref_roundtrip_and_default", () => {
  const s = memoryStorage();
  assert.equal(readPref(s, PREF_KEYS.mode, ["scan", "type"], "scan"), "scan");
  writePref(s, PREF_KEYS.mode, "type");
  assert.equal(readPref(s, PREF_KEYS.mode, ["scan", "type"], "scan"), "type");
  writePref(s, PREF_KEYS.sound, "off");
  assert.equal(readPref(s, PREF_KEYS.sound, ["on", "off"], "on"), "off");
});

test("test_readPref_ignores_unknown_value", () => {
  const s = memoryStorage();
  s.setItem(PREF_KEYS.mode, "camera");
  assert.equal(readPref(s, PREF_KEYS.mode, ["scan", "type"], "scan"), "scan");
});

test("test_readPref_storage_that_throws_or_is_missing", () => {
  assert.equal(readPref(throwing, PREF_KEYS.sound, ["on", "off"], "on"), "on");
  assert.equal(readPref(null, PREF_KEYS.sound, ["on", "off"], "on"), "on");
  assert.doesNotThrow(() => writePref(throwing, PREF_KEYS.sound, "off"));
  assert.doesNotThrow(() => writePref(undefined, PREF_KEYS.sound, "off"));
});

test("test_bottomInset_keyboard_and_toolbar", () => {
  assert.equal(bottomInset(844, null), 0);
  assert.equal(bottomInset(844, { height: 844, offsetTop: 0 }), 0);
  // iOS keyboard: the visual viewport shrinks, the layout viewport stays.
  assert.equal(bottomInset(844, { height: 508, offsetTop: 0 }), 336);
  // Scrolled while the keyboard is open.
  assert.equal(bottomInset(844, { height: 508, offsetTop: 100 }), 236);
  // A toolbar animation's few pixels do not count.
  assert.equal(bottomInset(844, { height: 820, offsetTop: 0 }), 0);
});

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
  LINK_KEY,
  countStatuses,
  endCounts,
  endTone,
  forgetLinkFragment,
  readPref,
  sessionCheck,
  shortCode,
  shortStatus,
  statusDetail,
  statusTone,
  summaryText,
  takeLinkFragment,
  writePref,
} from "../enroll/ui.js";

test("test_shortStatus_glossary_badges", () => {
  // dev/glossary.md, "Certificate states".
  assert.equal(shortStatus("stored"), "added");
  assert.equal(shortStatus("unassigned"), "no device yet");
  assert.equal(shortStatus("already_stored"), "already known");
  assert.equal(shortStatus("conflict"), "conflict");
  assert.equal(shortStatus("invalid"), "invalid");
  assert.equal(shortStatus("error"), "failed");
  assert.equal(shortStatus("weird"), "weird");
});

test("test_shortStatus_unassigned_never_reads_as_done", () => {
  assert.notEqual(shortStatus("unassigned"), "added");
  assert.equal(statusTone("unassigned"), "wait");
  assert.equal(
    statusDetail({ status: "unassigned" }),
    "no device in your project has this serial number; bussard matches it once it finds the device (bussard scan)",
  );
});

test("test_statusTone_groups", () => {
  assert.equal(statusTone("stored"), "good");
  assert.equal(statusTone("already_stored"), "good");
  for (const s of ["conflict", "invalid", "error", "rejected"]) assert.equal(statusTone(s), "bad");
  for (const s of ["queued", "sending", "sent"]) assert.equal(statusTone(s), "pending");
});

test("test_statusDetail_added_names_device", () => {
  assert.equal(statusDetail({ status: "stored", ia: "1.1.3", name: "Kitchen actuator" }), "for 1.1.3 Kitchen actuator");
  assert.equal(statusDetail({ status: "stored", ia: "1.1.12" }), "for 1.1.12");
  assert.equal(statusDetail({ status: "stored" }), "");
});

test("test_statusDetail_drops_redundant_lines", () => {
  // The badge says it; bussard's message does not add a line either.
  assert.equal(statusDetail({ status: "already_stored", message: "bussard already had this certificate" }), "");
  assert.equal(
    statusDetail({ status: "conflict", message: "the key store holds another factory key for 1.1.3" }),
    "your key store holds a different key for this device",
  );
  assert.equal(statusDetail({ status: "invalid", message: "bad check" }), "check the code");
});

test("test_statusDetail_reason_for_failed_and_not_sent", () => {
  assert.equal(statusDetail({ status: "error", message: "key store is locked" }), "key store is locked");
  assert.equal(
    statusDetail({ status: "rejected", message: "The relay's limit for this session is reached." }),
    "The relay's limit for this session is reached.",
  );
  assert.equal(statusDetail({ status: "error" }), "");
});

test("test_shortCode_first_and_last_group", () => {
  assert.equal(shortCode("AAFDHWABCDEFGHIJKLMNOPQRSTUVWXX4VCNL"), "AAFDHW \u2026 X4VCNL");
});

test("test_countStatuses_groups", () => {
  assert.deepEqual(
    countStatuses(["stored", "stored", "unassigned", "already_stored", "conflict", "invalid", "error", "rejected", "sent", "queued"]),
    {
      total: 10,
      sent: 9,
      added: 2,
      noDevice: 1,
      known: 1,
      conflict: 1,
      invalid: 1,
      failed: 1,
      notSent: 1,
      inFlight: 2,
    },
  );
});

test("test_summaryText_glossary_example", () => {
  const statuses = ["stored", "already_stored", "already_stored", "already_stored", "already_stored", "unassigned"];
  assert.equal(summaryText(statuses), "6 sent · 1 added · 4 already known · 1 no device yet");
});

test("test_summaryText_problems_and_in_flight", () => {
  assert.equal(
    summaryText(["stored", "conflict", "conflict", "invalid", "error", "sending", "rejected"]),
    "6 sent · 1 added · 2 conflicts · 1 invalid · 1 failed · 1 waiting · 1 not sent",
  );
});

test("test_summaryText_empty_and_singular", () => {
  assert.equal(summaryText([]), "Nothing sent yet");
  assert.equal(summaryText(["sending"]), "1 sent · 1 waiting");
  assert.equal(summaryText(["conflict"]), "1 sent · 1 conflict");
  assert.equal(summaryText(["rejected"]), "1 not sent");
});

test("test_endCounts_glossary_example", () => {
  const statuses = ["stored", "already_stored", "already_stored", "already_stored", "already_stored", "already_stored"];
  assert.equal(endCounts(statuses, 1), "Sent 6 certificates to your bussard: 1 added, 5 already known.");
});

test("test_endCounts_from_page_results_not_closed_stored", () => {
  // closed.stored counts only added ones; the page's tally is the record.
  assert.equal(
    endCounts(["stored", "unassigned", "conflict"], 1),
    "Sent 3 certificates to your bussard: 1 added, 1 no device yet, 1 conflict.",
  );
  assert.equal(endCounts(["stored", "sent"]), "Sent 2 certificates to your bussard: 1 added, 1 without an answer.");
  assert.equal(endCounts(["sent"]), "Sent 1 certificate to your bussard: 1 without an answer.");
});

test("test_endCounts_nothing_sent", () => {
  assert.equal(endCounts([]), "No certificates were sent from this page.");
  assert.equal(endCounts(["rejected"]), "No certificates were sent from this page.");
  // After a reload the page has no results; bussard's count stands in.
  assert.equal(endCounts([], 2), "bussard added 2 certificates in this session.");
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
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
}

const throwing = {
  getItem() {
    throw new Error("SecurityError");
  },
  removeItem() {
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

const FRAGMENT = "v=1&s=AAAAAAAAAAAAAAAAAAAAAA&k=BBBB";

test("test_takeLinkFragment_keeps_link_for_reload", () => {
  const s = memoryStorage();
  assert.equal(takeLinkFragment(`#${FRAGMENT}`, s), FRAGMENT);
  assert.equal(s.getItem(LINK_KEY), FRAGMENT);
  // Reload after the page removed the fragment from the address bar.
  assert.equal(takeLinkFragment("", s), FRAGMENT);
});

test("test_takeLinkFragment_new_link_replaces_kept_one", () => {
  const s = memoryStorage();
  takeLinkFragment(`#${FRAGMENT}`, s);
  assert.equal(takeLinkFragment("#v=1&s=CCCC", s), "v=1&s=CCCC");
  assert.equal(takeLinkFragment("", s), "v=1&s=CCCC");
});

test("test_takeLinkFragment_nothing_kept_or_storage_refused", () => {
  assert.equal(takeLinkFragment("", memoryStorage()), "");
  assert.equal(takeLinkFragment("", null), "");
  assert.equal(takeLinkFragment("", throwing), "");
  // The address bar's link still works without storage.
  assert.equal(takeLinkFragment(`#${FRAGMENT}`, throwing), FRAGMENT);
});

test("test_forgetLinkFragment_clears", () => {
  const s = memoryStorage();
  takeLinkFragment(`#${FRAGMENT}`, s);
  forgetLinkFragment(s);
  assert.equal(takeLinkFragment("", s), "");
  assert.doesNotThrow(() => forgetLinkFragment(throwing));
  assert.doesNotThrow(() => forgetLinkFragment(null));
});

test("test_sessionCheck_open", () => {
  assert.equal(sessionCheck(200, { messages: [], closed: false }), "open");
  assert.equal(sessionCheck(200, { messages: [{ seq: 1, body: {} }] }), "open");
});

test("test_sessionCheck_unknown_or_expired_is_gone", () => {
  assert.equal(sessionCheck(404, null), "gone");
  assert.equal(sessionCheck(404, { error: "not found" }), "gone");
});

test("test_sessionCheck_closed_session_has_ended", () => {
  // After bussard's DELETE the relay answers closed until expiry.
  assert.equal(sessionCheck(200, { messages: [], closed: true }), "ended");
});

test("test_sessionCheck_relay_failure_is_unreachable", () => {
  assert.equal(sessionCheck(500, null), "unreachable");
  assert.equal(sessionCheck(400, { error: "bad" }), "unreachable");
  assert.equal(sessionCheck(200, null), "unreachable");
  assert.equal(sessionCheck(200, { closed: false }), "unreachable");
});

test("test_endTone_all_good_is_info", () => {
  assert.equal(endTone([]), "info");
  assert.equal(endTone(["stored", "already_stored", "unassigned"]), "info");
});

test("test_endTone_any_problem_is_warn", () => {
  for (const bad of ["conflict", "invalid", "error", "rejected", "sent", "queued"]) {
    assert.equal(endTone(["stored", "already_stored", bad]), "warn", bad);
  }
});

test("test_endCounts_problem_order_matches_summary", () => {
  const statuses = ["error", "invalid", "conflict", "unassigned", "already_stored", "stored"];
  assert.equal(
    endCounts(statuses),
    "Sent 6 certificates to your bussard: 1 added, 1 already known, 1 no device yet, 1 conflict, 1 invalid, 1 failed.",
  );
  assert.equal(summaryText(statuses), "6 sent · 1 added · 1 already known · 1 no device yet · 1 conflict · 1 invalid · 1 failed");
});

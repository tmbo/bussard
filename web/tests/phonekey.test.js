// The kept phone key of the enrolment page (web/enroll/phonekey.js) over an
// in-memory backend. Run: node --test web/tests/*.test.js

import { test } from "node:test";
import assert from "node:assert/strict";

import { generatePhoneKey } from "../enroll/enroll.js";
import { PHONE_KEY_MAX_AGE_MS, PhoneKeys, indexedDbBackend } from "../enroll/phonekey.js";

const subtle = globalThis.crypto.subtle;

function mapBackend() {
  const map = new Map();
  return {
    map,
    get: async (k) => map.get(k),
    put: async (k, v) => void map.set(k, v),
    delete: async (k) => void map.delete(k),
    keys: async () => [...map.keys()],
  };
}

test("test_PhoneKeys_save_and_load_the_same_phone", async () => {
  const keys = new PhoneKeys(mapBackend());
  const phone = await generatePhoneKey(subtle);
  assert.equal(phone.privateKey.extractable, false);
  await keys.save("sid1", phone);
  const back = await keys.load("sid1");
  assert.equal(back.privateKey, phone.privateKey);
  assert.deepEqual(back.publicRaw, phone.publicRaw);
  assert.equal(back.nextId, 1);
  assert.equal(back.confirmed, false);
  assert.equal(await keys.load("other"), null);
});

test("test_PhoneKeys_next_id_and_confirmation_survive_a_reload", async () => {
  const backend = mapBackend();
  const phone = await generatePhoneKey(subtle);
  await new PhoneKeys(backend).save("sid1", phone);
  await new PhoneKeys(backend).setNextId("sid1", 4);
  await new PhoneKeys(backend).setConfirmed("sid1");
  const back = await new PhoneKeys(backend).load("sid1");
  assert.equal(back.nextId, 4);
  assert.equal(back.confirmed, true);
  // Updates for a session with no kept key write nothing.
  await new PhoneKeys(backend).setNextId("none", 9);
  assert.equal(backend.map.has("none"), false);
});

test("test_PhoneKeys_forget_and_expiry", async () => {
  let now = 1_000_000;
  const backend = mapBackend();
  const keys = new PhoneKeys(backend, () => now);
  const phone = await generatePhoneKey(subtle);
  await keys.save("ended", phone);
  await keys.forget("ended");
  assert.equal(await keys.load("ended"), null);

  await keys.save("old", phone);
  now += PHONE_KEY_MAX_AGE_MS - 1;
  await keys.save("young", phone);
  assert.notEqual(await keys.load("old"), null);
  now += 2;
  // Loading any session drops every key past the maximum session length.
  assert.notEqual(await keys.load("young"), null);
  assert.equal(backend.map.has("old"), false);
});

test("test_PhoneKeys_without_storage", async () => {
  const none = new PhoneKeys(null);
  await none.save("sid", await generatePhoneKey(subtle));
  assert.equal(await none.load("sid"), null);
  const failing = new PhoneKeys({
    get: async () => {
      throw new Error("blocked");
    },
    put: async () => {
      throw new Error("blocked");
    },
    delete: async () => {
      throw new Error("blocked");
    },
    keys: async () => {
      throw new Error("blocked");
    },
  });
  await failing.save("sid", await generatePhoneKey(subtle));
  await failing.forget("sid");
  assert.equal(await failing.load("sid"), null);
  assert.equal(await indexedDbBackend(undefined), null);
});

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const kem = require('..');

function flip(buf, i) {
  const out = buf.slice();
  out[i] ^= 0x01;
  return out;
}

test('decapsulate rejects wrong secret-key length', () => {
  const kp = kem.generateKeypair();
  const e = kem.encapsulate(kp.publicKey);
  for (const bad of [2399, 2401, 0]) {
    const sk = new Uint8Array(bad);
    sk.set(kp.secretKey.subarray(0, Math.min(bad, kp.secretKey.length)));
    assert.throws(() => kem.decapsulate(sk, e.ciphertext), RangeError);
  }
});

test('decapsulate rejects wrong ciphertext length', () => {
  const kp = kem.generateKeypair();
  for (const bad of [1087, 1089, 0]) {
    assert.throws(() => kem.decapsulate(kp.secretKey, new Uint8Array(bad)), RangeError);
  }
});

test('decapsulate rejects non-buffer inputs by type', () => {
  assert.throws(() => kem.decapsulate(null, new Uint8Array(1088)), TypeError);
  assert.throws(() => kem.decapsulate('00', new Uint8Array(1088)), TypeError);
});

test('encapsulate rejects wrong public-key length', () => {
  for (const bad of [1183, 1185, 0]) {
    assert.throws(() => kem.encapsulate(new Uint8Array(bad)));
  }
});

test('encapsulate rejects a non-canonical encapsulation key (FIPS 203 7.2)', () => {
  const kp = kem.generateKeypair();
  const bad = kp.publicKey.slice();
  // First 12-bit coefficient -> 0xFFF (4095), which is >= q = 3329.
  bad[0] = 0xff;
  bad[1] = (bad[1] & 0xf0) | 0x0f;
  assert.equal(kem.encapsKeyCheck(bad), false, 'probe must be non-canonical');
  assert.throws(() => kem.encapsulate(bad), /canonical|modulus|invalid/i);
});

test('tampered ciphertext is rejected implicitly, not by throwing', () => {
  const kp = kem.generateKeypair();
  const e = kem.encapsulate(kp.publicKey);
  let seen = new Set();
  for (let i = 0; i < 64; i++) {
    const ct = flip(e.ciphertext, (i * 17) % e.ciphertext.length);
    const ss1 = kem.decapsulate(kp.secretKey, ct);
    const ss2 = kem.decapsulate(kp.secretKey, ct);
    assert.equal(ss1.length, 32);
    assert.deepEqual(Buffer.from(ss1), Buffer.from(ss2), 'implicit rejection must be deterministic');
    assert.notDeepEqual(Buffer.from(ss1), Buffer.from(e.sharedSecret));
    seen.add(Buffer.from(ss1).toString('hex'));
  }
  assert.ok(seen.size >= 60, `rejection secrets must depend on ct, got ${seen.size} distinct`);
});

test('non-canonical decapsulation key is rejected when it cannot be parsed', () => {
  const kp = kem.generateKeypair();
  const bad = kp.secretKey.slice();
  bad[0] ^= 0xff;
  // FIPS 203 7.3 does not require a modulus check on dk; a flipped byte must
  // still produce a well-formed rejection secret rather than a crash.
  const out = kem.decapsulate(bad, new Uint8Array(1088));
  assert.equal(out.length, 32);
});

test('decapsulate enforces the FIPS 203 7.3 decapsulation-key check', () => {
  const kp = kem.generateKeypair();
  const e = kem.encapsulate(kp.publicKey);
  const pkOff = 3 * 384;
  const hOff = pkOff + 1184;

  const badH = kp.secretKey.slice();
  badH[hOff] ^= 0x01;
  assert.equal(kem.decapsKeyCheck(badH), false, 'probe must fail the key check');
  assert.throws(() => kem.decapsulate(badH, e.ciphertext), /inconsistent|H\(ek\)/i);

  const badPk = kp.secretKey.slice();
  badPk[pkOff] ^= 0x01;
  assert.throws(() => kem.decapsulate(badPk, e.ciphertext), /inconsistent|H\(ek\)/i);
});

test('extreme lengths are rejected before touching the buffer body', () => {
  const kp = kem.generateKeypair();
  const huge = new Uint8Array(8 * 1024 * 1024);
  const t0 = process.hrtime.bigint();
  assert.throws(() => kem.decapsulate(kp.secretKey, huge), RangeError);
  assert.throws(() => kem.encapsulate(huge), RangeError);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(ms < 200, 'length checks must be O(1): ' + ms.toFixed(1) + 'ms');
});

test('type confusion is rejected at every entry point', () => {
  const kp = kem.generateKeypair();
  const ct = new Uint8Array(1088);
  for (const v of [null, undefined, 'x', 42, {}, [], new ArrayBuffer(1088)]) {
    assert.throws(() => kem.decapsulate(v, ct), TypeError);
    assert.throws(() => kem.decapsulate(kp.secretKey, v), TypeError);
    assert.throws(() => kem.encapsulate(v), TypeError);
  }
});

test('derand entry points reject wrong seed lengths', () => {
  const kp = kem.generateKeypair();
  for (const n of [0, 31, 33, 64]) {
    assert.throws(() => kem.generateKeypairDerand(new Uint8Array(n), new Uint8Array(32)), /32 bytes/);
    assert.throws(() => kem.generateKeypairDerand(new Uint8Array(32), new Uint8Array(n)), /32 bytes/);
  }
  for (const n of [0, 31, 33]) {
    assert.throws(() => kem.encapsulateDerand(kp.publicKey, new Uint8Array(n)), /32 bytes/);
  }
});

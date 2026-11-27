// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const kem = require('..');

// Node 18 has webcrypto but does not expose it as a global; @noble/post-quantum
// reads crypto.getRandomValues, so give it the same backend the KEM uses.
if (typeof globalThis.crypto === 'undefined') {
  Object.defineProperty(globalThis, 'crypto', {
    value: require('node:crypto').webcrypto,
    configurable: true,
    writable: true
  });
}

const N = Number(process.env.PROPERTY_ROUNDS || 200);
const CROSS = Number(process.env.CROSS_ROUNDS || 100);

function eq(a, b) { return Buffer.from(a).equals(Buffer.from(b)); }

test(`roundtrip holds for ${N} random keypairs`, () => {
  for (let i = 0; i < N; i++) {
    const kp = kem.generateKeypair();
    const e = kem.encapsulate(kp.publicKey);
    const ss = kem.decapsulate(kp.secretKey, e.ciphertext);
    assert.ok(eq(ss, e.sharedSecret), `roundtrip failed at i=${i}`);
  }
});

test('fresh encapsulation is randomized (ct and ss differ)', () => {
  const kp = kem.generateKeypair();
  const seenCt = new Set(), seenSs = new Set();
  for (let i = 0; i < 100; i++) {
    const e = kem.encapsulate(kp.publicKey);
    seenCt.add(Buffer.from(e.ciphertext).toString('hex'));
    seenSs.add(Buffer.from(e.sharedSecret).toString('hex'));
  }
  assert.equal(seenCt.size, 100, 'ciphertexts must not repeat');
  assert.equal(seenSs.size, 100, 'shared secrets must not repeat');
});

test('a one-bit change always changes the decapsulated secret', () => {
  const kp = kem.generateKeypair();
  const e = kem.encapsulate(kp.publicKey);
  for (let i = 0; i < 100; i++) {
    const ct = e.ciphertext.slice();
    const pos = (i * 31) % ct.length;
    ct[pos] ^= 1 << (i % 8);
    const ss = kem.decapsulate(kp.secretKey, ct);
    assert.ok(!eq(ss, e.sharedSecret), `tamper not detected at pos=${pos}`);
  }
});

test(`interoperates with @noble/post-quantum in both directions (${CROSS} rounds)`, async () => {
  const { ml_kem768: noble } = await import('@noble/post-quantum/ml-kem.js');
  for (let i = 0; i < CROSS; i++) {
    const nk = noble.keygen();
    const mine = kem.encapsulate(nk.publicKey);
    const theirSs = noble.decapsulate(mine.ciphertext, nk.secretKey);
    assert.ok(eq(theirSs, mine.sharedSecret), `noble<-ours failed at i=${i}`);

    const mk = kem.generateKeypair();
    const theirs = noble.encapsulate(mk.publicKey);
    const mySs = kem.decapsulate(mk.secretKey, theirs.cipherText);
    assert.ok(eq(mySs, theirs.sharedSecret), `ours<-noble failed at i=${i}`);
  }
});

test('implicit rejection matches noble byte-for-byte', async () => {
  const { ml_kem768: noble } = await import('@noble/post-quantum/ml-kem.js');
  for (let i = 0; i < 20; i++) {
    const nk = noble.keygen();
    const e = noble.encapsulate(nk.publicKey);
    const ct = e.cipherText.slice();
    ct[(i * 13) % ct.length] ^= 1;
    const theirs = noble.decapsulate(ct, nk.secretKey);
    const ours = kem.decapsulate(nk.secretKey, ct);
    assert.ok(eq(ours, theirs), `J(z||c) mismatch at i=${i}`);
    assert.ok(!eq(ours, e.sharedSecret));
  }
});

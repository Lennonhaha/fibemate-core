// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const kem = require('..');
const params = require('../src/kem/params.js');

test('parameter-set registry is queryable', () => {
  assert.ok(params.listParamSets().includes('ML-KEM-768'));
  assert.equal(params.validateParamSet('ML-KEM-768'), true);
  assert.equal(params.validateParamSet('ml-kem-768'), false);
  assert.equal(params.validateParamSet('ML-KEM-999'), false);
  const p = params.getParams('ML-KEM-768');
  assert.equal(p.k, 3);
  assert.equal(p.du, 10);
  assert.equal(p.dv, 4);
  assert.equal(params.getParams('ML-KEM-768').N, 256);
});

test('encapsKeyCheck accepts a fresh key and rejects malformed ones', () => {
  const kp = kem.generateKeypair();
  assert.equal(kem.encapsKeyCheck(kp.publicKey), true);
  assert.equal(kem.encapsKeyCheck(kp.publicKey.subarray(0, 1183)), false);
  assert.equal(kem.encapsKeyCheck(null), false);
  const bad = kp.publicKey.slice();
  bad[0] = 0xff; bad[1] = (bad[1] & 0xf0) | 0x0f;
  assert.equal(kem.encapsKeyCheck(bad), false);
});

test('decapsKeyCheck verifies length and the stored H(ek)', () => {
  const kp = kem.generateKeypair();
  assert.equal(kem.decapsKeyCheck(kp.secretKey), true);
  assert.equal(kem.decapsKeyCheck(kp.secretKey.subarray(0, 2399)), false);
  assert.equal(kem.decapsKeyCheck(null), false);
  const bad = kp.secretKey.slice();
  bad[3 * 384 + 1184] ^= 0xff; // first byte of stored H(ek)
  assert.equal(kem.decapsKeyCheck(bad), false);
});

test('byteEncode/byteDecode are inverse on canonical values', () => {
  const poly = new Int16Array(256);
  for (let i = 0; i < 256; i++) poly[i] = (i * 37) % 3329;
  const enc = kem.byteEncode(poly, 12);
  assert.equal(enc.length, 384);
  assert.deepEqual(kem.byteDecode(enc, 12), poly);
});

test('samplePoly(seed, nonce) packs rho||j||i like sampleNTT', () => {
  const seed = new Uint8Array(32).map((_, i) => i + 1);
  for (const [i, j] of [[1, 2], [2, 1], [0, 0]]) {
    const nonce = (i << 8) | j;
    const packed = new Uint8Array(34);
    packed.set(seed); packed[32] = j; packed[33] = i;
    assert.deepEqual(kem.samplePoly(seed, nonce), kem.sampleNTT(packed));
  }
});

test('CBD samplers stay inside eta bounds and are deterministic', () => {
  const buf = new Uint8Array(192).map((_, i) => (i * 7) & 0xff);
  const a = kem.cbd(buf, 2), b = kem.cbd2(buf);
  assert.deepEqual(a, b);
  for (const v of a) assert.ok(v >= -2 && v <= 2);
  const c = kem.cbd(buf, 3);
  for (const v of c) assert.ok(v >= -3 && v <= 3);
});

test('modular arithmetic closes over Q', () => {
  const Q = 3329;
  for (const [a, b] of [[0, 0], [1, Q - 1], [Q - 1, Q - 1], [1234, 2345]]) {
    assert.ok(kem.modAdd(a, b) >= 0 && kem.modAdd(a, b) < Q);
    assert.ok(kem.modSub(a, b) >= 0 && kem.modSub(a, b) < Q);
    assert.ok(kem.modMul(a, b) >= 0 && kem.modMul(a, b) < Q);
    assert.equal(kem.modAdd(a, kem.modNeg(a)), 0);
  }
});

test('constant-time helpers select and compare without leaking shape', () => {
  const a = Uint8Array.from([1, 2, 3]);
  const b = Uint8Array.from([9, 9, 9]);
  assert.deepEqual(kem.ctSelectU8(a, b, 255), a);
  assert.deepEqual(kem.ctSelectU8(a, b, 0), b);
  assert.equal(kem.ctEqMask(a, a), 255);
  assert.equal(kem.ctEqMask(a, b), 0);
  assert.throws(() => kem.ctEqMask(a, b.subarray(0, 2)), RangeError);
});

test('zeroize helpers clear every element', () => {
  const u8 = Uint8Array.from([1, 2, 3]);
  kem.zeroizeU8(u8);
  assert.deepEqual(u8, Uint8Array.from([0, 0, 0]));
  const i16 = Int16Array.from([4, 5]);
  kem.zeroizeI16(i16);
  assert.deepEqual(i16, Int16Array.from([0, 0]));
  const vec = [Int16Array.from([1, 1]), Int16Array.from([2, 2])];
  kem.zeroizePolyVec(vec);
  assert.deepEqual(vec, [Int16Array.from([0, 0]), Int16Array.from([0, 0])]);
});

test('NTT-domain vector addition is element-wise', () => {
  const a = [Int16Array.from([1, 2]), Int16Array.from([3, 4])];
  const b = [Int16Array.from([10, 20]), Int16Array.from([30, 40])];
  const r = kem.vecAddNTT(a, b, 2);
  assert.deepEqual(Array.from(r[0].slice(0, 2)), [11, 22]);
  assert.deepEqual(Array.from(r[1].slice(0, 2)), [33, 44]);
  assert.equal(r[0].length, 256);
});

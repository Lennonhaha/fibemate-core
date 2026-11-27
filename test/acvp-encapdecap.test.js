// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
//
// ACVP ML-KEM encapDecap (FIPS 203) - encapsulation, decapsulation (including
// implicit-rejection cases) and the two key checks, with vectors from NIST.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const kem = require('..');
const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'mlkem-encapdecap.json'), 'utf8'));

const hexToBytes = h => Uint8Array.from(Buffer.from(h, 'hex'));
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const by = fn => VECTORS.groups.filter(g => g.function === fn && g.parameterSet === 'ML-KEM-768');

for (const group of by('encapsulation')) {
  test(`ACVP ${group.parameterSet} encapsulation tgId=${group.tgId} (${group.tests.length})`, () => {
    kem.loadParams(group.parameterSet);
    const failures = [];
    for (const v of group.tests) {
      const r = kem.encapsulateDerand(hexToBytes(v.ek), hexToBytes(v.m));
      const cOk = eq(r.ciphertext, hexToBytes(v.expectedC));
      const kOk = eq(r.sharedSecret, hexToBytes(v.expectedK));
      if (!cOk || !kOk) failures.push({ tcId: v.tcId, cOk, kOk });
    }
    if (failures.length) console.error('first failure:', failures[0]);
    assert.equal(failures.length, 0, `${failures.length} encapsulation cases failed`);
  });
}

for (const group of by('decapsulation')) {
  test(`ACVP ${group.parameterSet} decapsulation tgId=${group.tgId} (${group.tests.length})`, () => {
    kem.loadParams(group.parameterSet);
    const failures = [];
    for (const v of group.tests) {
      const k = kem.decapsulate(hexToBytes(v.dk), hexToBytes(v.c));
      if (!eq(k, hexToBytes(v.expectedK))) failures.push({ tcId: v.tcId });
    }
    if (failures.length) console.error('first failure:', failures[0]);
    assert.equal(failures.length, 0, `${failures.length} decapsulation cases failed`);
  });
}

for (const group of by('decapsulationKeyCheck').concat(by('encapsulationKeyCheck'))) {
  test(`ACVP ${group.parameterSet} ${group.function} tgId=${group.tgId} (${group.tests.length})`, () => {
    kem.loadParams(group.parameterSet);
    const failures = [];
    for (const v of group.tests) {
      const got = group.function === 'encapsulationKeyCheck'
        ? kem.encapsKeyCheck(hexToBytes(v.ek))
        : kem.decapsKeyCheck(hexToBytes(v.dk));
      if (got !== v.expectedTestPassed) failures.push({ tcId: v.tcId, got, expected: v.expectedTestPassed });
    }
    if (failures.length) console.error('first failure:', failures[0]);
    assert.equal(failures.length, 0, `${failures.length} ${group.function} cases failed`);
  });
}

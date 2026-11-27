// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
//
// ACVP ML-KEM keyGen (FIPS 203) - known-answer vectors from NIST.
// Vectors: test/vectors/mlkem-keygen.json (provenance and pinned upstream blob
// SHAs are recorded in the file; source usnistgov/ACVP-Server, FIPS 203).
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const kem = require('..');
const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'mlkem-keygen.json'), 'utf8'));

const hexToBytes = h => Uint8Array.from(Buffer.from(h, 'hex'));
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));

const groups = VECTORS.groups.filter(g => g.parameterSet === 'ML-KEM-768');

test('ACVP vector provenance is pinned', () => {
  assert.ok(VECTORS.provenance && VECTORS.provenance.files.length === 2);
  for (const f of VECTORS.provenance.files) {
    assert.match(f.blob_sha, /^[0-9a-f]{40}$/);
    assert.match(f.sha256, /^[0-9a-f]{64}$/);
  }
});

for (const group of groups) {
  test(`ACVP ${group.parameterSet} keyGen tgId=${group.tgId} (${group.tests.length} cases)`, () => {
    kem.loadParams(group.parameterSet);
    const failures = [];
    for (const v of group.tests) {
      const kp = kem.generateKeypairDerand(hexToBytes(v.d), hexToBytes(v.z));
      const ekOk = eq(kp.publicKey, hexToBytes(v.ek));
      const dkOk = eq(kp.secretKey, hexToBytes(v.dk));
      if (!ekOk || !dkOk) failures.push({ tcId: v.tcId, ekOk, dkOk });
    }
    if (failures.length) console.error('first failure:', failures[0]);
    assert.equal(failures.length, 0, `${failures.length} keyGen cases failed`);
  });
}

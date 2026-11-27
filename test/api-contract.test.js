// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const kem = require(ROOT);
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

test('exports the documented API surface', () => {
  for (const name of ['generateKeypair', 'encapsulate', 'decapsulate',
    'generateKeypairDerand', 'encapsulateDerand', 'HybridKeyExchange',
    'encapsKeyCheck', 'decapsKeyCheck']) {
    assert.equal(typeof kem[name], 'function', `${name} must be a function`);
  }
  assert.equal(typeof kem.sha3_256, 'function');
});

test('encoded sizes are the FIPS 203 ML-KEM-768 sizes', () => {
  const kp = kem.generateKeypair();
  const e = kem.encapsulate(kp.publicKey);
  assert.equal(kp.publicKey.length, 1184);
  assert.equal(kp.secretKey.length, 2400);
  assert.equal(e.ciphertext.length, 1088);
  assert.equal(e.sharedSecret.length, 32);
});

test('derand entry points are deterministic and read-only', () => {
  const d = new Uint8Array(32).fill(7);
  const z = new Uint8Array(32).fill(9);
  const m = new Uint8Array(32).fill(11);
  const before = { d: d.slice(), z: z.slice(), m: m.slice() };

  const kp1 = kem.generateKeypairDerand(d, z);
  const kp2 = kem.generateKeypairDerand(d, z);
  const e1 = kem.encapsulateDerand(kp1.publicKey, m);
  const e2 = kem.encapsulateDerand(kp2.publicKey, m);

  assert.deepEqual(Buffer.from(kp1.publicKey), Buffer.from(kp2.publicKey));
  assert.deepEqual(Buffer.from(kp1.secretKey), Buffer.from(kp2.secretKey));
  assert.deepEqual(Buffer.from(e1.ciphertext), Buffer.from(e2.ciphertext));
  assert.deepEqual(Buffer.from(e1.sharedSecret), Buffer.from(e2.sharedSecret));
  assert.deepEqual(d, before.d);
  assert.deepEqual(z, before.z);
  assert.deepEqual(m, before.m);
});

test('HybridKeyExchange (ECDH P-256 + ML-KEM-768) agrees on both sides', async () => {
  const a = new kem.HybridKeyExchange();
  const b = new kem.HybridKeyExchange();
  const ai = await a.initialize();
  const bi = await b.initialize();
  const send = await a.encapsulateToPeer(bi.kemPublicKey, bi.ecdhPublicKey);
  const got = await b.decapsulateFromPeer(send.ciphertext, ai.ecdhPublicKey);
  assert.equal(got.length, 32);
  assert.deepEqual(Buffer.from(got), Buffer.from(send.sharedSecret));
});

test('package.json files whitelist is complete and exists', () => {
  for (const rel of pkg.files) {
    assert.ok(fs.existsSync(path.join(ROOT, rel)), `listed file missing: ${rel}`);
  }
  const required = ['index.js', 'src/kem/ml-kem-768.js', 'src/kem/fips203.js', 'src/kem/params.js'];
  for (const rel of required) assert.ok(pkg.files.includes(rel), `files[] omits ${rel}`);
});

test('npm pack contains exactly the whitelisted shipped files', () => {
  const raw = execSync('npm pack --dry-run --json --silent', {
    cwd: ROOT, encoding: 'utf8', timeout: 120000
  });
  const info = JSON.parse(raw)[0];
  const packed = info.files.map(f => f.path).sort();
  const expected = [...pkg.files, 'package.json'].sort();
  assert.deepEqual(packed, expected);
});

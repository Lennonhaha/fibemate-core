// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
/**
 * FIPS 203 known-answer regression.
 *
 * Vectors: test/kat/mlkem-768-KAT.rsp (100 records, deterministic derivation
 * documented in the file header). Each record checks three things:
 *   1. KeyGen(d, z) reproduces ek and dk byte-for-byte
 *   2. Encaps(ek, m) reproduces c and k
 *   3. Decaps(dk, c) returns the same k
 *
 * A roundtrip-only suite cannot catch a divergence here: both sides can be
 * wrong in the same way. That is exactly what happened before 0.1.1.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const kem = require('../src/kem/ml-kem-768.js');

const rspPath = path.join(__dirname, 'kat', 'mlkem-768-KAT.rsp');

function parseRsp(text) {
    const records = [];
    let cur = null;
    for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        const m = /^([A-Za-z0-9_]+)\s*=\s*(\S+)$/.exec(line);
        if (!m) continue;
        const [, key, value] = m;
        if (key === 'count') {
            if (cur) records.push(cur);
            cur = { count: Number(value) };
        } else if (cur) {
            cur[key] = value;
        }
    }
    if (cur) records.push(cur);
    return records;
}

function hex(s) { return Buffer.from(s, 'hex'); }
function same(a, b) { const x = Buffer.from(a); const y = Buffer.from(b); return x.length === y.length && x.equals(y); }
function short(s) { return s.slice(0, 16) + '…'; }

const records = parseRsp(fs.readFileSync(rspPath, 'utf8'));
if (records.length !== 100) {
    console.error('FAIL: expected 100 KAT records, found ' + records.length);
    process.exit(1);
}

let pass = 0;
const failures = [];

for (const r of records) {
    const d = hex(r.seed);
    const z = hex(r.z);
    const m = hex(r.m);

    const kp = kem.generateKeypairDerand(d, z);
    if (!same(kp.publicKey, hex(r.ek))) {
        failures.push('count ' + r.count + ': ek mismatch');
        continue;
    }
    if (!same(kp.secretKey, hex(r.dk))) {
        failures.push('count ' + r.count + ': dk mismatch');
        continue;
    }

    const enc = kem.encapsulateDerand(kp.publicKey, m);
    if (!same(enc.ciphertext, hex(r.c))) {
        failures.push('count ' + r.count + ': ciphertext mismatch');
        continue;
    }
    if (!same(enc.sharedSecret, hex(r.k))) {
        failures.push('count ' + r.count + ': shared secret mismatch (got ' + short(enc.sharedSecret.toString('hex')) + ', want ' + short(r.k) + ')');
        continue;
    }

    const dec = kem.decapsulate(kp.secretKey, enc.ciphertext);
    if (!same(dec, hex(r.k))) {
        failures.push('count ' + r.count + ': decapsulated secret mismatch');
        continue;
    }

    pass++;
}

if (failures.length) {
    console.error('FAIL: ' + pass + '/' + records.length + ' records passed');
    for (const f of failures.slice(0, 10)) console.error('  ' + f);
    if (failures.length > 10) console.error('  … ' + (failures.length - 10) + ' more');
    process.exit(1);
}

console.log('PASS: ' + pass + '/' + records.length + ' FIPS 203 KAT records');

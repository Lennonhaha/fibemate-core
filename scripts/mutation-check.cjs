// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
/**
 * Mutation gate.
 *
 * A test that cannot fail is decoration. This script re-introduces each defect
 * that was actually found in production (or in review), runs the KAT, and
 * requires the KAT to go red. If a mutation survives, the tests are not
 * guarding the behaviour they claim to guard and the gate exits 1.
 *
 * The file is always restored, including on crash or Ctrl-C.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const kAT = path.join(root, 'test', 'kat-mlkem768.test.js');

const mutations = [
    {
        name: 'keygen drops the FIPS 203 domain separator k',
        file: 'src/kem/fips203.js',
        from: 'sha3_512(new Uint8Array([...d,K]))',
        to: 'sha3_512(new Uint8Array([...d]))'
    },
    {
        name: 'matrix nonce order swapped (rho||i||j instead of rho||j||i)',
        file: 'src/kem/fips203.js',
        from: 'seed.set(rho);seed[32]=j;seed[33]=i;',
        to: 'seed.set(rho);seed[32]=i;seed[33]=j;'
    },
    {
        name: 'encapsulation drops H(ek) from the KDF input',
        file: 'src/kem/fips203.js',
        from: 'const G=sha3_512(new Uint8Array([...m,...hpk]));',
        to: 'const G=sha3_512(new Uint8Array([...m]));'
    }
];

function runKat() {
    return spawnSync(process.execPath, [kAT], { cwd: root, encoding: 'utf8' });
}

const control = runKat();
if (control.status !== 0) {
    console.error('FAIL: baseline KAT is already red; fix the tests before mutating');
    console.error(control.stdout || '');
    console.error(control.stderr || '');
    process.exit(1);
}

let survivors = 0;
for (const m of mutations) {
    const abs = path.join(root, m.file);
    const original = fs.readFileSync(abs, 'utf8');
    const count = original.split(m.from).length - 1;
    if (count !== 1) {
        console.error('FAIL: mutation target not found exactly once: ' + m.name + ' (found ' + count + ')');
        survivors++;
        continue;
    }
    try {
        fs.writeFileSync(abs, original.split(m.from).join(m.to), 'utf8');
        const res = runKat();
        if (res.status === 0) {
            console.error('SURVIVED: ' + m.name + ' — KAT still passed, the test does not cover this');
            survivors++;
        } else {
            console.log('KILLED:   ' + m.name);
        }
    } finally {
        fs.writeFileSync(abs, original, 'utf8');
    }
}

const restored = runKat();
if (restored.status !== 0) {
    console.error('FAIL: KAT does not pass after restoring the sources');
    process.exit(1);
}

if (survivors) {
    console.error('FAIL: ' + survivors + ' mutation(s) survived');
    process.exit(1);
}
console.log('PASS: ' + mutations.length + '/' + mutations.length + ' mutations killed, sources restored');

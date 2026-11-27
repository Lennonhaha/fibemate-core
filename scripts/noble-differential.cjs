// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
'use strict';

// Preflight differential: 100 rounds in each direction against an independent
// implementation. This is the check that would have caught fibemate-core@0.1.0:
// it round-tripped against itself but could not talk to anything else.

if (typeof globalThis.crypto === 'undefined') {
  Object.defineProperty(globalThis, 'crypto', {
    value: require('node:crypto').webcrypto,
    configurable: true,
    writable: true
  });
}

const ROUNDS = Number(process.env.DIFF_ROUNDS || 100);
const kem = require('..');

function same(a, b) {
  return Buffer.from(a).equals(Buffer.from(b));
}

(async () => {
  const { ml_kem768: noble } = await import('@noble/post-quantum/ml-kem.js');
  let oursToTheirs = 0;
  let theirsToOurs = 0;

  for (let i = 0; i < ROUNDS; i++) {
    // noble generates, we encapsulate, noble decapsulates.
    const nk = noble.keygen();
    const mine = kem.encapsulate(nk.publicKey);
    const theirSs = noble.decapsulate(mine.ciphertext, nk.secretKey);
    if (!same(theirSs, mine.sharedSecret)) {
      throw new Error(`noble<-ours failed at round ${i}`);
    }
    oursToTheirs++;

    // we generate, noble encapsulates, we decapsulate.
    const kp = kem.generateKeypair();
    const theirs = noble.encapsulate(kp.publicKey);
    const mySs = kem.decapsulate(kp.secretKey, theirs.cipherText);
    if (!same(mySs, theirs.sharedSecret)) {
      throw new Error(`ours<-noble failed at round ${i}`);
    }
    theirsToOurs++;
  }

  console.log(`differential OK: noble<-ours ${oursToTheirs}/${ROUNDS}, ours<-noble ${theirsToOurs}/${ROUNDS}`);
})().catch((err) => {
  console.error(`differential FAILED: ${err.message}`);
  process.exit(1);
});

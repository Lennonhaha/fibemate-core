#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
'use strict';

// The smallest useful demo: Alice and Bob each generate a keypair, Alice
// encapsulates a shared secret to Bob's public key, Bob decapsulates it.
// The "message" is XORed with that secret only to make the point visual;
// ML-KEM is a KEM, not an encryption scheme — use the shared secret with an
// AEAD in real code.
//
//   node examples/minimal-chat.js

const { generateKeypair, encapsulate, decapsulate } = require('..');

const alice = generateKeypair();
const bob = generateKeypair();
console.log(`alice ek ${alice.publicKey.length} B, dk ${alice.secretKey.length} B`);
console.log(`bob   ek ${bob.publicKey.length} B, dk ${bob.secretKey.length} B`);

const message = Buffer.from('hello from alice');
const { ciphertext, sharedSecret } = encapsulate(bob.publicKey); // Alice -> Bob
const bobSecret = decapsulate(bob.secretKey, ciphertext);        // Bob's side

const wire = Buffer.from(message.map((b, i) => b ^ sharedSecret[i % sharedSecret.length]));
const opened = Buffer.from(wire.map((b, i) => b ^ bobSecret[i % bobSecret.length]));

console.log(`ciphertext ${ciphertext.length} B, shared secret ${sharedSecret.length} B`);
console.log(`bob recovered: ${opened.toString('utf8')}`);
if (!opened.equals(message)) {
  console.error('shared secrets disagree — this must never happen');
  process.exit(1);
}

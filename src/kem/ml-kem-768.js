// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
/**
 * fibemate-core — ML-KEM-768 entry point.
 *
 * The KEM primitives live in ./fips203.js. The previous implementation in this
 * file was Kyber round-3: it derived (rho, sigma) from G(d) without the FIPS 203
 * domain separator k, sampled the matrix with a truncated one-byte nonce, and
 * used the round-3 KDF (K = H(K_bar || H(ct))) instead of G(m || H(ek)). It was
 * self-consistent, which is why the roundtrip tests passed, but it failed every
 * NIST-style KAT and could not interoperate with a conforming implementation.
 *
 * HybridKeyExchange is kept here because it is a fibemate-core API, not a KEM
 * primitive; it now composes the FIPS 203 primitives below.
 */
'use strict';

const fips = require('./fips203.js');

const {
    generateKeypair,
    encapsulate,
    decapsulate,
    sha3_256
} = fips;

// ============================================================================
// Hybrid Key Exchange (ECDH P-256 + ML-KEM-768)
// ============================================================================
class HybridKeyExchange {
    constructor() {
        this.kemKeypair = null;
        this.ecdhKeypair = null;
    }
    async initialize() {
        this.kemKeypair = generateKeypair();
        this.ecdhKeypair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
        );
        return {
            kemPublicKey: this.kemKeypair.publicKey,
            ecdhPublicKey: await crypto.subtle.exportKey('raw', this.ecdhKeypair.publicKey)
        };
    }
    async encapsulateToPeer(pk, ecdhPk) {
        const k = encapsulate(pk);
        const e = await crypto.subtle.importKey('raw', ecdhPk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        const d = await crypto.subtle.deriveBits({ name: 'ECDH', public: e }, this.ecdhKeypair.privateKey, 256);
        const c = new Uint8Array(64);
        c.set(k.sharedSecret, 0);
        c.set(new Uint8Array(d), 32);
        return { ciphertext: k.ciphertext, sharedSecret: sha3_256(c) };
    }
    async decapsulateFromPeer(ct, ecdhPk) {
        const ks = decapsulate(this.kemKeypair.secretKey, ct);
        const e = await crypto.subtle.importKey('raw', ecdhPk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        const d = await crypto.subtle.deriveBits({ name: 'ECDH', public: e }, this.ecdhKeypair.privateKey, 256);
        const c = new Uint8Array(64);
        c.set(ks, 0);
        c.set(new Uint8Array(d), 32);
        return sha3_256(c);
    }
}

const MLKEM768 = Object.assign({}, fips, {
    generateKeypair,
    encapsulate,
    decapsulate,
    HybridKeyExchange,
    // Deterministic entry points (KAT / ACVP only).
    generateKeypairDerand: fips.generateKeypairDerand,
    encapsulateDerand: fips.encapsulateDerand
});

module.exports = MLKEM768;

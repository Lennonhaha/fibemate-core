# Releases

What shipped, and what the CI record actually says about it.

## 2026-11-15 — v0.1.0

- Run [43672042765](https://github.com/Lennonhaha/fibemate-core/actions/runs/43672042765)
  concluded `failure` at step "Confirm the registry sees the release" (03:22:26Z).
- Step "Publish with provenance" succeeded (03:22:18Z–03:22:26Z). The npm registry
  recorded `fibemate-core@0.1.0` at 2026-11-15T03:25:34Z, with a Sigstore attestation.
- Cause: the run was built from `0e6dcbd`, whose confirm step was a single
  `npm view` with no retry. A brand-new package is not always indexed the moment
  the publish returns, so that check read a 404 that meant "not yet visible",
  not "not published".
- `639db43` (2026-11-15T03:26:29Z, PR #5) replaced the bare check with an 18 × 10s
  poll that also reports staged publishing instead of a bare 404.

The red run is a false negative for publish status, not a failed release. The
package is on the registry and its provenance verifies; only the confirmation
step was wrong.

## 2026-11-27 — v0.1.1

- Replaces the 0.1.0 ML-KEM-768 implementation, which was not FIPS 203 and not
  interoperable with any standard implementation: the matrix nonce was truncated
  to one byte (`(i<<8)|j` into a `Uint8Array`), KeyGen used `G(d)` without the
  `k` domain separator, and Encaps/Decaps used the round-3 KDF.
- Evidence: 100/100 ACVP-derived KAT records, mutation gate 3/3 killed, and
  `@noble/post-quantum` interop passing in both directions (including the
  published tarball, re-downloaded and retested).
- Run [45936057416](https://github.com/Lennonhaha/fibemate-core/actions/runs/45936057416)
  published `fibemate-core@0.1.1` at 2026-11-27T03:47:44Z with Sigstore provenance;
  the `latest` dist-tag moved to 0.1.1.
- `0.1.0` is deprecated on npm. Keys generated with it must be discarded; 0.1.1
  deliberately has no fallback because the failure mode is silent, not an error.

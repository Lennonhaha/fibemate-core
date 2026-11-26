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

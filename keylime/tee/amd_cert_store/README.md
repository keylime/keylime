# AMD ASK/ARK trust anchors

Per-generation AMD SEV-SNP certificate chains used as the default trust
anchors by the az-snp-vtpm TEE verifier (`keylime/tee/az_snp_vtpm.py`).
The VCEK certificate carried in the attestation evidence is validated
against the chain matching the report's processor generation.

The verifier resolves its anchors from a local store only and never
fetches them from the network: by default this directory, or the one
configured with the `amd_anchor_path` option in the `[verifier]` section
of verifier.conf.

| File              | Generation | CPUs      | Source (AMD KDS)                                  |
|-------------------|------------|-----------|---------------------------------------------------|
| milan_ask_ark.pem | Milan      | EPYC 7003 | https://kdsintf.amd.com/vcek/v1/Milan/cert_chain  |
| genoa_ask_ark.pem | Genoa      | EPYC 9004 | https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain  |
| turin_ask_ark.pem | Turin      | EPYC 9005 | https://kdsintf.amd.com/vcek/v1/Turin/cert_chain  |

The SHA-256 of each file is pinned in test/test_az_snp_vtpm.py
(BundledAnchorTest), so any change to a bundled anchor fails the test
suite and must be a conscious, reviewed edit.

## Refreshing or adding a chain

Run from a trusted network. fetch_kds_chain() validates the bundle's
internal consistency only (ARK self-signed, ASK signed by the ARK,
generation names match); it cannot authenticate the source. The
sha256 diff in the pull request that lands the refreshed file is the
authenticity check.

    python - <<'PY'
    from cryptography.hazmat.primitives import serialization
    from keylime.tee.az_snp_vtpm import fetch_kds_chain

    generation = "milan"  # or "genoa" / "turin"
    ask, ark = fetch_kds_chain(generation)
    with open(f"{generation}_ask_ark.pem", "wb") as f:
        f.write(ask.public_bytes(serialization.Encoding.PEM))
        f.write(ark.public_bytes(serialization.Encoding.PEM))
    PY

Commit the result together with an updated sha256 pin in the test.

Adding a new CPU generation means adding a new file. If AMD ever
rotates a generation's chain, keep the previous file until evidence
signed under it is no longer accepted; note that the loader accepts
one chain per generation, so a replacement drops support for older
evidence -- call that out in the commit message.

TODO: add a CI canary that fetches the current chains from the AMD
KDS and diffs them against the bundled ones, alerting on rotation or
staleness. Alert-only: it must never update the store, because the
KDS cannot authenticate itself. It needs a network opt-in so offline
CI runs can skip it.

These are public certificates published by AMD's Key Distribution
Service; they contain no secrets.

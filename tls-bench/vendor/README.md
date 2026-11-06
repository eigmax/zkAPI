`p384` is crates.io `p384` 0.13.1 with one change for the Ziren-patched `ecdsa`
0.16.9, which adds `VerifyPrimitive::HIGH_S_ALLOWED`: `src/ecdsa.rs` sets it to
`true`, as the patched `p256` does (X.509 and TLS accept high-S signatures).

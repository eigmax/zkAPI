# TLS 1.3 session check in Ziren: cycles and proving time

Cycles: execution only, Ziren at `a3c5a48a`, interpreter (`ZIREN_DISABLE_JIT=1`).
Proving time: see [Proving time](#proving-time-one-gpu).
Each capture is a real TLS 1.3 session (`TLS_AES_128_GCM_SHA256`, X25519) to a
public LLM API, sent without credentials, so the reply is a 401/403/400. The
handshake and record layer are the same as for an authenticated call.

The guest (`guest/`, logic in `tlsv/`) recomputes the key schedule from the
client's X25519 secret, opens every handshake record, checks the chain to a
pinned anchor (names, CA flags, the leaf's SAN), the server's
`CertificateVerify` and `Finished`, the client's `Finished`, opens all
application records with their tags, and opens the request's `"model"` field
block by block without a tag.

## Totals

| Host | Chain (signatures) | Anchor = root | Anchor = intermediate |
|---|---|---|---|
| api.anthropic.com | P-256 leaf, P-384 intermediate | 91.6 M | 4.88 M |
| api.openai.com | same | 91.7 M | 4.98 M |
| openrouter.ai | same | 91.8 M | 5.03 M |
| api.together.xyz | same | – | 4.98 M |
| api.mistral.ai | same | – | 4.99 M |
| generativelanguage.googleapis.com | same | 91.8 M | 5.03 M |
| api.deepseek.com | RSA-2048 leaf and intermediate, RSA-PSS CertificateVerify | 10.2 M | 8.32 M |

## Where the cycles go (api.anthropic.com)

| Phase | Cycles | Note |
|---|---|---|
| intermediate's signature (P-384 / SHA-384) | 86.66 M | no P-384 precompile; same certificate for every connection |
| X25519 | 3.19 M | software Montgomery ladder; no precompile used |
| open handshake records (2.6 KB, AES-128-GCM) | 0.56 M | about 210 cycles/byte |
| leaf's signature (P-256) | 0.26 M | secp256r1 precompile |
| CertificateVerify (P-256) | 0.26 M | secp256r1 precompile |
| X.509 parse + name/CA/SAN checks | 0.18 M | |
| key schedule (HKDF) | 0.10 M | SHA-256 precompile |
| transcript hash, Finished | 0.02 M | |
| open request (274 B) + response (553 B) | 0.30 M | 200–330 cycles/byte with tags |
| selective decrypt of 3 blocks (`"model":...`) | 0.02 M | about 6 k cycles/block, no tag |

RSA-2048 signatures cost about 1.77 M cycles each (u256×2048 precompile).

## Reading

- With the intermediate pinned (it changes a few times a year and can be
  checked once), a full handshake check costs about **5 M cycles**, or
  **8.3 M** for an RSA chain.
- After that, X25519 is two thirds of the cost. An X25519 precompile, or
  computing it through the Edwards precompile, is the next lever.
- Per audited request on an already-proven connection: about 20 k cycles to
  open the `model` field, or about 0.3 M to open a 1 KB exchange with its tags.
- No AES precompile is needed at these sizes: AES-GCM is under 15 % of a
  pinned-anchor handshake.

## Proving time (one GPU)

One RTX 5090, Ziren's GPU prover built against Ziren `main` at `a4d47079`,
stage `compress` (core shards plus the recursive compression into one proof;
the compression overlaps the core proof, so it adds almost nothing after it).
One process proved the three captures in this order: `anthropic-pinned` four
times, `deepseek-pinned` three times, `anthropic` three times. The first proof
of the process carries the CUDA start-up and is left out. Settings: shard size
2^22 + 1, `TRACE_GEN_WORKERS=16`, verification of the result off.

| Capture | Cycles (prover) | Shards | Proofs | Time per proof | Mean |
|---|---|---|---|---|---|
| api.anthropic.com, intermediate pinned | 4.99 M | 5 | 3 warm | 2.37 / 3.99 / 3.83 s | **3.4 s** |
| api.anthropic.com, root anchor (P-384) | 91.75 M | 31 | 3 | 9.88 / 8.19 / 8.16 s | **8.7 s** |
| api.deepseek.com (RSA-2048), intermediate pinned | 8.47 M | 6 | 3 | 23.95 / 27.32 / 22.70 s | **24.7 s** |

Every result is one compressed proof of 290,530 bytes (284 KiB).

### Through shrink and wrap

A second process ran stage `wrap`: the same core and compress, then shrink,
then the wrap over BN254, which is the STARK that the Groth16 or PLONK circuit
verifies. Every wrap proof was verified. Order: `anthropic-pinned` four times
(the first cold, left out), then `deepseek-pinned` twice, then `anthropic`
twice.

| Capture | Core + compress | Shrink | Wrap | Total, mean |
|---|---|---|---|---|
| Anthropic, intermediate pinned | 3.81 / 3.76 / 3.63 s | 0.41 / 0.33 / 0.35 s | 1.00 / 1.17 / 1.22 s | **5.2 s** |
| Anthropic, root anchor | 9.08 / 7.96 s | 0.35 / 0.40 s | 0.82 / 1.90 s | **10.3 s** |
| DeepSeek, intermediate pinned | 22.09 / 19.12 s | 0.37 / 0.36 s | 2.18 / 0.87 s | **22.5 s** |

Shrink takes about 0.35 s and wrap 0.8–2.2 s, whatever the capture: both
prove a fixed-shape verifier circuit. Together they add about 1.5 s to every
proof. The Groth16 or PLONK proof over the wrap (gnark) was not run.

Reading:

- A pinned-anchor handshake proves in about 3.4 s. The cold first proof took
  13.9 s.
- The P-384 chain is 18 times the cycles but only 2.6 times the time
  (11 MHz against 1.5 MHz). A small proof is dominated by fixed costs per
  proof, not by its cycles.
- The RSA chain proves 7 times slower than the P-256 one for 1.7 times the
  cycles. Execution alone takes 2.1–3.8 s here against 0.05 s for the P-256
  capture. The patched `rsa` crate runs its big-number division in
  unconstrained blocks (38 of them, with 77 hint reads). Those instructions
  are not counted as cycles, but they run again every time the prover
  re-executes the guest. This is the likely cause and has not been profiled.

## Not covered

- Certificate validity periods and revocation (the guest has no clock).
- HelloRetryRequest, other cipher suites or groups (the client offers only these).
- The Groth16/PLONK proof over the wrap, and proving on more than one GPU.

## Run

Build on a machine with the Ziren toolchain, with Ziren checked out as a
sibling of this repository:

```sh
cargo build --release -p capture -p host
target/release/capture api.anthropic.com /v1/messages claude-sonnet-4-5 data/anthropic.bin
ZIREN_DISABLE_JIT=1 target/release/host data/anthropic.bin data/anthropic-pinned.bin
```

`p384` is vendored with one change for the Ziren-patched `ecdsa`; see `vendor/README.md`.
Full output of the run above: `data/run.log`.

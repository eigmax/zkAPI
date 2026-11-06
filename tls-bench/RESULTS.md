# TLS 1.3 session check in Ziren: cycles

Execution only (no proof), Ziren at `a3c5a48a`, interpreter (`ZIREN_DISABLE_JIT=1`).
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

## Not covered

- Certificate validity periods and revocation (the guest has no clock).
- HelloRetryRequest, other cipher suites or groups (the client offers only these).
- Proving time: these are executor cycles. Precompile calls cost few cycles but
  add rows to their own tables.

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

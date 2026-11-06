# zkAPI

Experiments toward verifiable LLM routing: a router that proves, with the
[Ziren](https://github.com/ProjectZKM/Ziren) zkVM, which model it called and
what it billed, on top of zkAPI-style anonymous usage credits.

## The service

An LLM router resells access to model providers (Anthropic, OpenAI, Google,
DeepSeek and others) behind one API and one balance. Two things about such a
router are hard to check today:

- **Privacy.** The router sees every prompt and can link it to the paying
  account.
- **Honesty.** Users cannot tell whether a request went to the model they
  asked for, or whether the tokens they were billed match what the provider
  returned.

[zkAPI](https://github.com/ethereum/zkapi) solves the first. A user deposits
into an on-chain vault and pays for each request with a zero-knowledge proof,
so the server cannot link requests to a deposit. It does not solve the
second: the server's word about what it served is final.

This service adds the second guarantee on top of an unchanged zkAPI vault:

1. **Receipts and a log.** For each lease, the router keeps a log of the
   upstream calls (model, token counts, price) and signs a receipt for the
   user.
2. **Epoch proof.** At the end of each epoch, a Ziren proof shows that every
   charge follows from the log and the published price card. The proof also
   commits to the log's Merkle root.
3. **Sampled zkTLS audit.** A public randomness beacon picks about 1% of
   requests after the epoch ends. For each one, the router proves in Ziren
   that it held a genuine TLS 1.3 session with the provider, and opens only
   the `model` and usage fields. A witness proxy, run by another party, records
   the ciphertext so the router cannot invent a session later.
4. **Bond.** The router posts a bond on chain. A missing audit proof, or a
   receipt that disagrees with the log, slashes it. Only the disputed lease
   is revealed.

Users keep zkAPI's privacy and pay nothing extra. The router pays the
proving cost, about 17 s of compute per audited request (see below).

The only proofs published are the Groth16 wraps. Ziren's core, compress and
shrink proofs are not zero-knowledge and would leak the TLS secrets, so they
stay with the router.

## Status

| Part | State |
|---|---|
| TLS 1.3 session check in a Ziren guest | done: cycles and proving time measured, [`tls-bench/`](tls-bench) |
| Deployment of zkAPI and Ziren's verifier on GOAT testnet3 and Metis Sepolia | guide written, [`deploy/`](deploy) |
| Router, per-lease log, receipts | planned |
| Epoch guest (log checks, price card, Merkle root) | planned |
| Witness proxy | planned |
| Bond contract | planned |

## Measured so far

| Step | Result |
|---|---|
| TLS 1.3 check, intermediate pinned | 4.9–5.0 M cycles (P-256 chain), 8.3 M (RSA-2048) |
| STARK proof to the wrap, one RTX 5090 | 5.2 s (P-256 pinned) |
| Groth16 over the wrap, CPU | 11.5 s, after a one-time 50 s circuit load |
| Proof on chain | 260 bytes |

Details and the remaining gaps are in
[`tls-bench/RESULTS.md`](tls-bench/RESULTS.md).

## Layout

- [`tls-bench/`](tls-bench): checks a recorded TLS 1.3 session with a public
  LLM API inside a Ziren guest and reports the cycles of each step and the
  proving time.
- [`deploy/`](deploy): deploying zkAPI and Ziren's verifier on GOAT testnet3
  and Metis Sepolia, the fork changes each chain needs, and who maintains each
  component.

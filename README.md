# zkAPI on Ziren

The [zkAPI](https://github.com/ethereum/zkapi) v2 request and withdrawal
statements, proven by the [Ziren](https://github.com/ProjectZKM/Ziren) zkVM
instead of zkAPI's circuit-specific Groth16.

zkAPI lets a user pay for API calls from an on-chain deposit without linking
the calls to the deposit or to each other. Each call carries a request proof
that the payer owns a funded, unspent note, and a nullifier the server accepts
only once. When the user leaves, the vault pays out the final balance against a
withdrawal proof. This repository keeps both statements as they are and
replaces only the proof system.

## What changes

| Unchanged | Replaced |
|---|---|
| Vault, server and wallet protocol | Groth16 circuits → one Rust guest per statement |
| Statements, public words and their encodings | Per-circuit trusted setup → Ziren's single Groth16 wrap |
| Poseidon, Baby-JubJub and Schnorr, with upstream's parameters | Groth16 prover in the browser → Ziren prover, GPU |
| Upstream fixtures and test vectors | Groth16 verifiers → Ziren's Groth16 verifier |

A guest reads the statement words and the witness, runs the circuit's checks
(Q1–Q10 for a request, W1–W14 for a withdrawal), and commits the statement
words as its public values: the `abi.encodePacked` `uint256` words. A proof is
a 260-byte Groth16 proof over those words and the guest's verifying-key hash.

## Status

| Part | State |
|---|---|
| Request and withdrawal statements as Ziren guests | done |
| Conformance tests against upstream's own circuits | done |
| Cycle cuts: hardcoded constants, BN254 Fr through `uint256_mulmod` | done |
| Prover CLI, with a serve mode that keeps the keys loaded | done |
| Request-proof verification inside the zkAPI server | not built; [`verify_groth16`](prover/src/lib.rs) is the check it would call |
| Solidity adapter so the vault accepts a withdrawal proof | not built; verify gas not measured |
| Hiding the witness from the prover (TEE) | deferred |

## Conformance

The checks follow the circuits' gadgets, not only upstream's native helpers:
points are checked to be on the curve, not in the subgroup; signature scalars
and blindings are any 251-bit integers; the Schnorr challenge is the full,
unreduced hash. [`conformance/tests/circuits.rs`](conformance/tests/circuits.rs)
runs upstream's Groth16 circuits (`zkapi_proof::groth16`) beside the Rust
statements:

| Test | Cases | Result |
|---|---|---|
| Valid statements | 3 requests, 5 withdrawals | accepted by both |
| Each request fixture with one value changed | 87 | same verdict; 69 refused by both |
| Each withdrawal fixture with one value changed | 165 | same verdict; 127 refused by both |
| Random mutated requests | 20 | same verdict |
| Encodings the circuit cannot take | 4 | refused |

## Results

Measured at Ziren `a4d47079`. These are measurements of the statements, not a
product timing.

Guest cycles per proof, one fixture each:

| Fixture | Arkworks | Constants hardcoded | Fr precompile |
|---|---|---|---|
| Signed request | 232.4 M | 192.4 M | 10.2 M |
| Genesis request | | 158.3 M | 7.6 M |
| Mutual-close withdrawal | | 116.0 M | 6.2 M |
| Escape withdrawal | 131.4 M | 91.6 M | 4.7 M |
| Ownership withdrawal | | 91.1 M | 4.3 M |

In the signed request, Poseidon takes 7.0 M cycles (4.7 M of them for the
Merkle path), the balance commitment 1.3 M and the Schnorr check 1.2 M.

Proving, one RTX 5090 and 88 CPU threads, in serve mode with the keys loaded:

| Fixture | Warm proof | Of which Groth16 on the CPU |
|---|---|---|
| Signed request | 21.5 s | 10.7–13.7 s |
| Escape withdrawal | 24.3 s | |
| Genesis request | 18.6 s | |

The first proof in a process takes 77.4 s, mostly reading the 29.7 M-constraint
Groth16 circuit. Every proof is 260 bytes and passes Ziren's Groth16 verifier.

For comparison, upstream's circuits have 23,507 (request) and 20,545
(withdrawal) constraints; its docs give about 279 ms to prove a withdrawal, a
256-byte proof, and 221k gas to verify one on chain.

## Trust

- **The prover sees the witness.** Ziren's STARKs are not zero-knowledge, so
  whoever runs the prover sees the note secret and could link the user's
  calls. Either the user runs the prover, or a TEE hides the witness; the TEE
  is deferred. Only the final Groth16 proof is shared.
- **Ziren's setup.** Every proof rests on Ziren's Groth16 wrap and its trusted
  setup. One setup serves every program, so zkAPI needs no ceremony of its own.
- **The guest code.** The Rust statements must accept exactly what the
  circuits accept; the conformance tests check this.

## Layout

- [`statement/`](statement): the two statements in Rust, the field, Poseidon
  and Baby-JubJub arithmetic, and the generated constants.
- [`guest/request`](guest/request), [`guest/withdrawal`](guest/withdrawal): the
  Ziren guests.
- [`prover/`](prover): the `zkapi-ziren` CLI and the Groth16 verification a
  server would run.
- [`conformance/`](conformance): upstream's fixtures, the tests against its
  circuits, and a tool that writes prover inputs.

## Usage

Building the guests needs Ziren's toolchain; the Groth16 step needs Go.

```sh
cargo test -p zkapi-ziren-statement
cargo test --release -p zkapi-ziren-conformance

# Write valid inputs to out/, then run or prove one.
cargo run --release -p zkapi-ziren-conformance --bin fixtures -- out
cargo run --release -p zkapi-ziren -- execute out/request-signed.bin
ZKM_PROVER=cuda cargo run --release -p zkapi-ziren -- prove out/request-signed.bin out/request-signed.proof

# Prove one `<input> <proof>` pair per line, keeping the keys loaded.
cargo run --release -p zkapi-ziren -- serve < jobs.txt

# Print both guests' verifying-key hashes.
cargo run --release -p zkapi-ziren -- vkeys
```

`statement/src/constants.rs` is generated by
`cargo run -p zkapi-ziren-statement --example constants`; the statement tests
check each value against its derivation.

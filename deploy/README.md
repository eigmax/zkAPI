# Deploying on GOAT testnet3 and Metis Sepolia

> **Parked.** This guide belongs to an earlier design, in which we ran our own
> router, users paid with zkAPI credits, and the router posted a bond on chain.
> The current plan works beside external routers (see the
> [README](../README.md)) and needs none of it. It is kept for reference.

What can be deployed today, what has to change first, and who maintains each
part once it runs.

The design adds three pieces to zkAPI: the router, the Ziren epoch and audit
proofs, and a bond contract. None of them is written yet. A testnet deployment
therefore starts with:

1. zkAPI itself, from a fork of
   [ethereum/zkapi](https://github.com/ethereum/zkapi) at `6fb229a`: the
   vault, its Groth16 adapter, the Poseidon runtime, the server, indexer and
   challenger;
2. Ziren's Groth16 verifier (`v2.0.0`), which the bond contract will call.

The bond contract is deployed once the epoch guest exists.

## The two chains

Probed on 2026-11-06 with [`preflight.sh`](preflight.sh), which makes
read-only calls against the public RPC.

| | GOAT testnet3 | Metis Sepolia |
|---|---|---|
| Chain ID | 48816 | 59902 |
| RPC | `https://rpc.testnet3.goat.network` (backup `https://rpc.ankr.com/goat_testnet`) | `https://sepolia.metisdevops.link` |
| Native coin | BTC | tMETIS |
| Cancun opcodes (`TSTORE`, `MCOPY`) | yes | **no** (revert) |
| `PUSH0` | yes | yes |
| EIP-1559 base fee | yes | **no** (blocks carry no `baseFeePerGas`) |
| `finalized` block tag | yes | yes |
| BN254 pairing precompile (`0x08`) | yes | yes |
| ERC-4337 EntryPoint v0.7 | **missing** | present |
| CREATE2 deployer `0x4e59…956c` | present | present |

GOAT runs zkAPI's contracts unchanged. Metis Sepolia does not: the vault, the
proof adapter and the paymaster use transient storage (EIP-1153). Deploy GOAT
first.

Run the probe again before deploying; testnets upgrade:

```sh
deploy/preflight.sh https://rpc.testnet3.goat.network https://sepolia.metisdevops.link
```

## Changes to the zkAPI fork

### Both chains

1. **Price feed.** `zkapi serverd` prices leases from `latestRoundData()`
   (selector `0xfeaf968c`) of a Chainlink-style feed, read at the `finalized`
   block, and the feed must price the chain's native coin in USD: BTC/USD on
   GOAT, METIS/USD on Metis.
   - DIA lists a BTC/USD feed on GOAT, but its testnet address and interface
     are unconfirmed.
   - Chainlink serves Metis mainnet; no Sepolia METIS/USD feed was found.
   - On testnets, deploy a Chainlink-compatible feed contract that a keeper
     updates. Set `--native-price-feed-decimals` and
     `--native-price-max-age-seconds` to match it.
2. **Price units.** Amounts are in units of 10⁻⁹ of the native coin
   (`native_asset_wei_per_unit` = 10⁹). The Ethereum defaults are the wrong
   size on GOAT:
   - `MIN_DEPOSIT=1000000` is 0.001 BTC;
   - a `REQUEST_CHARGE_CAP` of 50,000 is 5·10⁻⁵ BTC.

   Size both from each coin's price.
3. **Chain allowlists.** These accept only chains 1 and 11155111:
   - the challenger's signer, `docker/aws/signer/signer.mjs` (`ZKAPI_CHALLENGE_CHAIN_ID`);
   - zkapi-clientd's `cmd/zkapi-clientd/payment_qr.go` and `payment_quote.go`;
   - zkapi-clientd's packaged profiles, `internal/zkapi/deployments/*.json`, where each chain needs one;
   - `ZKAPI_TESTNET_PASSWORD`, which `crates/zkapi-serverd/src/config.rs` allows only on Sepolia.
4. **Gasless withdrawals.** Deploy with `GASLESS=0`. GOAT has no EntryPoint.
   The canonical one could be created later through the CREATE2 deployer.
5. **Indexer RPC.** The indexer needs `eth_call` by block hash (EIP-1898)
   with a gas cap of at least 0.6M, `eth_getBlockByHash`, and a provider other
   than the `rpc_url` that clients pin.
   - On GOAT, use the official RPC for clients and the Ankr backup for the
     indexer, or the reverse.
   - On Metis, a second provider is still to be found.

### Metis Sepolia only

6. **No transient storage.** Replace `ReentrancyGuardTransient` with a
   storage-slot guard, and the adapter's transient "withdrawal verified" slot
   with a storage slot cleared in the same call. Compile with
   `evm_version = "shanghai"`. This changes the vault's code hashes, so rerun
   the contract tests and `scripts/expected-codehashes.mjs`.
7. **Legacy transactions.** The signer signs only type-2 (EIP-1559)
   transactions, which Metis Sepolia cannot price. Add legacy (type-0)
   signing with an explicit `gasPrice` cap.

## Steps

The commands run from the root of the zkAPI fork. Each chain gets its own
seeds, database, indexer checkpoint and challenger account.

### 1. Signing keys

```sh
export ZKAPI_STATE_SEED=0x$(openssl rand -hex 31)
export ZKAPI_CLEAR_SEED=0x$(openssl rand -hex 31)
zkapi signing-keys     # prints the four public coordinates for the vault
```

The vault's keys are immutable. New keys need a new vault.

### 2. Price feed

Deploy the testnet feed and start its keeper. Note the address and the
decimals for the server flags and the manifest.

### 3. zkAPI contracts

```sh
cd demo/contracts
CHAIN_ID=48816 RPC_URL=https://rpc.testnet3.goat.network \
PRIVATE_KEY=… OWNER=<multisig> TREASURY=<address> \
STATE_SIGNING_KEY_X=… STATE_SIGNING_KEY_Y=… \
CLEARANCE_SIGNING_KEY_X=… CLEARANCE_SIGNING_KEY_Y=… \
SETUP_MANIFEST=$PWD/../../protocol/setup/v2-concession-dev/manifest.json ALLOW_DEV_SETUP=1 \
CHALLENGE_PERIOD_SECONDS=43200 MAX_PAUSE_DURATION_SECONDS=604800 \
REQUEST_CHARGE_CAP=… MIN_DEPOSIT=… GASLESS=0 \
OUTPUT_PATH=$PWD/../../.demo/goat-testnet3.json \
forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --broadcast
cd ../..
node scripts/expected-codehashes.mjs --deployment .demo/goat-testnet3.json.pending \
  --rpc "$RPC_URL" --finalize .demo/goat-testnet3.json --confirmations 12
```

`ALLOW_DEV_SETUP=1` uses zkAPI's single-party development setup. That is fine
on a testnet, never on a mainnet.

For Metis: `CHAIN_ID=59902`, its RPC, the contract changes above, and its own
output path.

### 4. Profiles

```sh
node scripts/deployment-profile.mjs --finalized .demo/goat-testnet3.json --format trusted   # server
node scripts/deployment-profile.mjs --finalized .demo/goat-testnet3.json --format sdk
node scripts/deployment-profile.mjs --finalized .demo/goat-testnet3.json --format clientd
```

### 5. Services, in this order

1. `zkapi-indexerd --chain-id 48816 --contract-address <vault> --rpc-url <indexer RPC> --from-block <deployBlock>`
2. `zkapi db init` against the trusted manifest.
3. The challenger and its signer, with a funded account used by nothing else.
4. `zkapi serverd`, with:
   - `--chain-id 48816 --deployment <trusted manifest>`
   - `--native-billing-rpc-url <RPC> --native-price-feed-address <feed>`
   - the seeds from step 1, taken from the environment.

The server refuses to start unless the seeds' keys equal the vault's. Its log
says `server signing keys match the vault's immutable keys`. The challenger
must be healthy before the first deposit. See zkAPI's `docs/deployment.md`
for every flag.

### 6. Ziren verifier

The verifier comes from the Groth16 circuit package that the Ziren SDK
installs under `~/.zkm/circuits/groth16/v2.0.0`. Use `ZKMVerifierGroth16.sol`
and `Groth16Verifier.sol` from there, plus `IZKMVerifier.sol` from Ziren's
`crates/recursion/gnark-ffi/assets`. Lay them out as the import expects:

```text
src/IZKMVerifier.sol
src/v2.0.0/ZKMVerifierGroth16.sol
src/v2.0.0/Groth16Verifier.sol
```

```sh
forge create src/v2.0.0/ZKMVerifierGroth16.sol:ZKMVerifier \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
cast call <verifier> "VERSION()(string)" --rpc-url "$RPC_URL"   # v2.0.0
```

The contract has no owner and no constructor arguments, and it needs nothing
beyond `PUSH0`, so the same build serves both chains. It checks a 260-byte
proof (a 4-byte verifier selector and eight words) against the program's key,
the public values' digest and its fixed `VK_ROOT`.

Prove with `VERIFY_VK=true`. A wrap proved without it fails the Groth16
circuit (`constraint … is not satisfied`).

### 7. Bond contract

Not written yet. It will call `verifyProof(programVKey, publicValues, proof)`
on the verifier above, with the epoch guest's key.

## Who maintains what

Parts marked *planned* do not exist yet.

| Component | Where it runs | Maintained by | Duties |
|---|---|---|---|
| `ZkApiVault`, its Groth16 adapter, Poseidon runtime | chain | **vault owner**, a multisig | Pause in an emergency; change the treasury (two-step). Signing keys, challenge period and minimum deposit are immutable: changing them means a new vault and a user migration. |
| Treasury | chain address | **treasury holder** | Receives spent balances and expired deposits. |
| Price feed (testnet) | chain + keeper | **feed keeper** | Post a round more often than `native_price_max_age_seconds`. Leases stop when the feed goes stale. |
| `zkapi serverd` (fork) | operator's servers | **router operator** | Hold the state and clearance seeds; back up the database (append-only request evidence); stay up through every challenge window. |
| `zkapi-indexerd` | operator's servers | **router operator** | Keep it synced from an RPC other than the clients' one; resync after a reorg. |
| Challenger and signer | operator's servers | **router operator** | Keep the exclusive account funded; answer every escape inside the challenge period. |
| Router *(planned)* | operator's servers | **router operator** | Hold provider API keys and capped per-lease keys; keep the per-lease log; sign user receipts. |
| Ziren prover *(planned)* | operator's GPUs | **router operator** | Prove each epoch and each sampled audit; publish only the Groth16 proof. The core, compress and shrink proofs are not zero-knowledge. |
| Witness proxy *(planned)* | separate host | **witness**: an auditor or the provider, never the router | Record the router's TLS ciphertext and sign its hash; never hold keys or plaintext. |
| Ziren verifier | chain | **nobody**: immutable, no owner | A new circuit version means deploying a new verifier and pointing the bond contract at it. |
| Bond contract *(planned)* | chain | **bond owner**, a multisig, for parameters only | The router posts the bond; anyone files a dispute; slashing follows the contract's rules. |
| Randomness beacon | public | **nobody** (for example drand) | The epoch pins which beacon round picks the sample. |
| Client SDK / zkapi-clientd | users' devices | **users** | Keep their notes and receipts; show a receipt only in a dispute. |
| Auditors | anywhere | **anyone** | Verify the published proofs and the epoch roots; file disputes. |
| Groth16 setup | repository | **zkAPI maintainers** | Testnets use the development setup. A mainnet needs their multi-party ceremony. |

The router operator runs most of the off-chain stack. Keep the parties
separate as follows:

- The witness must be another party. A witness run by the router could vouch
  for forged traffic.
- The vault and bond owners should be multisigs.
- The price feed's keeper should be a separate key from the operator's.

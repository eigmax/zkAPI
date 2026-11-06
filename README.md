# zkAPI

Reconciliation and dispute evidence for LLM calls made through third-party
routers such as [OpenRouter](https://openrouter.ai), with zkTLS proofs from the
[Ziren](https://github.com/ProjectZKM/Ziren) zkVM.

## The service

Companies buy model access through external routers. The router places each
call, picks the provider and sends the bill. Finance gets an invoice and the
router's own request log, and cannot tell which charges are right: whether a
call went to the model that was asked for, whether a fallback model was used,
and whether the tokens billed match the tokens used.

We sit beside the call path, not in it. Routing and billing stay with the
router. For each request we match three sources:

- the customer's own log: request id, model asked for, a hash of the prompt,
  and the router's id for the call;
- the router's record of the call, for example OpenRouter's
  [`GET /generation`](https://openrouter.ai/docs/api/api-reference/generations/get-generation):
  model, provider, token counts, cost and the upstream id;
- the invoice and the price list.

The result is a discrepancy list. Each item gives the amount, the evidence
source, how far it could be checked, and who should resolve it.

Every line carries one of three states:

| State | Meaning |
|---|---|
| Router-reported | The figure comes only from the router. |
| Bill reconciled | The customer's log, the router's record, the invoice and the price list agree. |
| Upstream verified | Checked against evidence the router does not control. |

### Without the router's cooperation

- **Reconciliation.** Find duplicate charges, prices that do not match the
  list, and fallbacks to a model that was not allowed. The model and the
  provider are router-reported.
- **Token recount.** Recount input tokens from the customer's prompts with the
  provider's tokenizer. Output tokens can be recounted roughly from the reply
  text. Reasoning tokens are never visible to the customer and cannot be
  recounted.
- **Provider reports.** For calls made with the customer's own provider keys
  (BYOK), compare with the provider's usage reports. These are totals by
  model, key and time, not per request.
- **zkTLS proof of what the router reported.** The customer holds the keys of
  its own TLS session with the router. A Ziren proof can show what the
  router's API returned for a call (model, usage and cost) while hiding the
  API key. In a dispute, the router cannot deny its own record. The proof
  shows what the router reported, not what happened upstream.

### With the router's cooperation

- The router sends its upstream traffic through a witness proxy run by another
  party. This is the arrangement of TLSNotary's
  [proxy mode](https://tlsnotary.org/docs/protocol/proxy-mode/).
- For a disputed call, the router proves in Ziren that it held a genuine TLS
  session with the provider, and opens only the model and usage fields.
- The witness must record every call of the billing period, because disputes
  are chosen afterwards.
- The router keeps its session secrets, and the witness keeps the ciphertext,
  for the dispute window. Together they reveal the prompts, so this needs the
  customer's data agreement.

Only the Groth16 wraps are shared. Ziren's core, compress and shrink proofs
are not zero-knowledge and would leak the TLS secrets.

## Status

| Part | State |
|---|---|
| TLS 1.3 session check in a Ziren guest, openrouter.ai included | done: cycles and proving time, [`tls-bench/`](tls-bench) |
| Reconciliation against OpenRouter's per-request records | planned |
| Token recount | planned |
| zkTLS proof of the router's API reply | planned; the session check it needs is measured |
| Witness proxy with a cooperating router | planned; needs a partner router |
| [`deploy/`](deploy) | parked: written for an earlier design that ran its own router |

## Measured so far

| Step | Result |
|---|---|
| TLS 1.3 check, intermediate pinned | 4.9–5.0 M cycles (P-256 chain; openrouter.ai 5.03 M), 8.3 M (RSA-2048) |
| STARK proof to the wrap, one RTX 5090 | 5.2 s (P-256 pinned) |
| Groth16 over the wrap, CPU | 11.5 s, after a one-time 50 s circuit load |
| Proof | 260 bytes |

Details and the remaining gaps are in
[`tls-bench/RESULTS.md`](tls-bench/RESULTS.md).

## Layout

- [`tls-bench/`](tls-bench): checks a recorded TLS 1.3 session with a public
  LLM API inside a Ziren guest and reports the cycles of each step and the
  proving time.
- [`deploy/`](deploy): parked. Deploying zkAPI and Ziren's verifier on GOAT
  testnet3 and Metis Sepolia, for the earlier design.

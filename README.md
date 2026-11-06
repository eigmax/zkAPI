# zkAPI

Reconcile third-party LLM bills, explain discrepancies, and attach verifiable
evidence where available. The bills are for calls made through routers such as
[OpenRouter](https://openrouter.ai); the evidence is checked in the
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

The result is a discrepancy list. Each line gives the amount, the next action,
and two separate fields: its resolution status and its evidence source.

| Status | Meaning |
|---|---|
| Open | A discrepancy is flagged, not yet resolved. |
| Confirmed | The evidence shows the charge is wrong. |
| Corrected | Refunded, credited or rebilled. |

| Evidence source | What it can show |
|---|---|
| Customer estimate | The customer's log and a local recount. It flags a line but cannot prove it. |
| Gateway report | The router's records and invoice: its own statement. |
| Provider aggregate | BYOK usage totals by model, key and period. It cannot verify a single invoice line. |
| Provider per-call evidence | A witnessed upstream exchange bound to the call. |

A recount that differs from the bill opens a line; it does not settle it,
since provider token counts can differ from a local recount for legitimate
reasons.

The reconciliation needs three things from the router: request ids that join
the customer's log to its records, per-call usage records we can read, and the
bill and price schedule for the same period. None of the three has been tested
with OpenRouter yet; so far only a TLS handshake with openrouter.ai has been
checked.

### Without the router's cooperation

- **Reconciliation.** Find duplicate charges, prices that do not match the
  list, and fallbacks to a model that was not allowed. The model and the
  provider are router-reported.
- **Token recount.** Estimate input tokens from the customer's prompts with
  the provider's tokenizer. Output tokens can be recounted roughly from the reply
  text. Reasoning tokens are never visible to the customer and cannot be
  recounted.
- **Provider reports.** For calls made with the customer's own provider keys
  (BYOK), compare with the provider's usage reports. These are totals by
  model, key and time, not per request.
- **Proof of what the router reported.** A TLS session proof alone is not
  enough here: the customer knows the session keys, so it could forge the
  router's reply. The `GET /generation` lookup must go through an independent
  witness that records the router's ciphertext as it arrives, or the router
  must sign a receipt. Ziren then checks the handshake, the chain and the
  recorded ciphertext, opens only the generation id, model, tokens and cost,
  and binds the result to the requested generation id. The proof shows what
  the router reported, not what happened upstream. Neither path is built
  yet.

### With the router's cooperation

- The router sends its upstream traffic through a witness proxy run by another
  party. This is the arrangement of TLSNotary's
  [proxy mode](https://tlsnotary.org/docs/protocol/proxy-mode/).
- For a disputed call, the router proves in Ziren that it held a genuine TLS
  session with the provider, and opens only the model and usage fields.
- Capture and proof are separate. Every eligible call in the agreed scope is
  captured as it happens; only disputed calls are proven afterwards. A call
  that was not captured cannot be proven later.
- The scope (keys, models, period) and the retention are agreed up front. The
  router keeps its session secrets, and the witness keeps the ciphertext, for
  the dispute window. Together they reveal the prompts, so this needs the
  customer's data agreement.
- The proof ties the upstream exchange to the customer's request, the response
  it received and the billed line.

Only the Groth16 wraps are shared. Ziren's core, compress and shrink proofs
are not zero-knowledge and would leak the TLS secrets.

## Status

| Part | State |
|---|---|
| TLS 1.3 session check in a Ziren guest, openrouter.ai included | done: cycles and proving time, [`tls-bench/`](tls-bench) |
| Reconciliation against OpenRouter's per-request records | planned |
| Token recount | planned |
| Witnessed proof of the router's `/generation` reply | planned; only the handshake check is measured |
| Witness proxy with a cooperating router | planned; needs a partner router |

## TLS benchmark

These numbers are for the TLS session check alone, not a product timing. The
captured replies are unauthenticated error responses, and the binding of the
wrap to the program's verifying key does not pass yet. An authenticated usage
lookup has not been measured.

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

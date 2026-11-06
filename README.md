# zkAPI

Experiments toward verifiable LLM routing: a router that proves, with the
[Ziren](https://github.com/ProjectZKM/Ziren) zkVM, which model it called and
what it billed, on top of zkAPI-style anonymous usage credits.

- [`tls-bench/`](tls-bench): checks a recorded TLS 1.3 session with a public
  LLM API inside a Ziren guest and reports the cycles of each step. Results in
  [`tls-bench/RESULTS.md`](tls-bench/RESULTS.md).
- [`deploy/`](deploy): deploying zkAPI and Ziren's verifier on GOAT testnet3
  and Metis Sepolia, the fork changes each chain needs, and who maintains each
  component.

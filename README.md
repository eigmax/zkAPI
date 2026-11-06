# zkAPI

Experiments toward verifiable LLM routing: a router that proves, with the
[Ziren](https://github.com/ProjectZKM/Ziren) zkVM, which model it called and
what it billed, on top of zkAPI-style anonymous usage credits.

- [`tls-bench/`](tls-bench): checks a recorded TLS 1.3 session with a public
  LLM API inside a Ziren guest and reports the cycles of each step. Results in
  [`tls-bench/RESULTS.md`](tls-bench/RESULTS.md).

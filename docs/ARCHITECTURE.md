# TRACE - Architecture

## Pattern

**Approach #2: Custom MCP Server** (the architecture the brief calls "the most
sound in the evaluation"), combined with a verification + self-correction loop.

## Components

```
  Case artifacts (read-only)
        │
        ▼
  ┌──────────────────────────┐     TRUST BOUNDARY (architectural)
  │  server/parsers.py        │  ← opens files 'r' only; no write/move/delete
  │  typed read-only tools    │     exists anywhere in this module
  └──────────────────────────┘
        │ list[Finding] + Citation per finding
        ▼
  ┌──────────────────────────┐
  │  server/trace_server.py   │  ← exposes ONLY 5 typed tools over MCP.
  │  MCP server               │     No execute_shell. No write_file. No delete.
  └──────────────────────────┘
        │ call_tool(name, **args)
        ▼
  ┌──────────────────────────┐
  │  agent/loop.py            │  plan → analyze → reason → verify → self-correct
  │  self-correcting loop     │  re-runs while claims are dropped,
  │                           │  capped by --max-iterations (default 3)
  └──────────────────────────┘
        │ every claim
        ▼
  ┌──────────────────────────┐     TRUST BOUNDARY (architectural)
  │  agent/verifier.py        │  ← finding is reportable ONLY if its citation
  │  citation verifier        │     matches a real line of raw tool output
  └──────────────────────────┘
        │ verified findings + dropped (UNVERIFIED) claims
        ▼
  logs/execution_log.jsonl     ← timestamped tool calls + token usage (audit trail)
```

## Where guardrails are enforced - architectural vs. prompt-based

| Guardrail | Type | Enforcement point |
|---|---|---|
| Agent cannot run destructive/shell commands | **Architectural** | `trace_server` exposes only typed read-only tools; `call_tool` raises on anything else |
| Evidence cannot be modified | **Architectural** | `parsers._read_lines` is the only disk access; opens `'r'`, no write methods called |
| No fabricated findings reach the report | **Architectural** | `verifier.verify_finding` checks every citation against raw bytes before a finding is reported |
| Inferred vs. confirmed findings distinguished | Data-model | `Finding.confidence` field, surfaced in output |
| Runaway loops prevented | **Architectural** | `--max-iterations` hard cap (default 3) in `loop.run_case` |

The loop **self-corrects**: after each pass the verifier reports which claims were
dropped, and if anything was dropped the agent re-runs told exactly which claims
to avoid - up to `--max-iterations` (default 3) passes. On `sample_data/case01`
it converges in 2 iterations (2 uncited claims dropped, then a clean pass).

There are **no prompt-based guardrails** in the trust-critical path. The agent's
behaviour is bounded by what the server exposes and what the verifier admits, not
by instructions it could ignore. (This is the failure mode the brief warns about
for Approach #4 / alternative IDEs - TRACE avoids it by construction.)

## Audit trail

`logs/execution_log.jsonl` records, per line: timestamp, event type, iteration,
tool name, arguments, finding count, estimated token usage, and per-finding
verification verdicts. Any reported finding's citation (`source_tool`,
`source_file`, `line_number`, `raw_line`) lets a judge trace it to the exact
execution that produced it.

## Swapping in real SIFT tools

Replace each function body in `server/parsers.py` with the real library call
(`regipy`, `python-evtx`, `analyzeMFT`, prefetch). The MCP contract, citation
model, verifier, loop, and benchmark are unchanged. The architecture is the
contribution; the parsers are pluggable.

# TRACE - Typed Read-only Artifact Citation Engine

## Inspiration

The brief is unusually honest: *"Protocol SIFT works. It also hallucinates more
than we'd like."* The judges are working DFIR practitioners and CISOs. They will
not be impressed by an agent that *sounds* like a senior analyst - they will ask
the question they ask every junior analyst: **"show me the evidence."** TRACE is
built around that single question.

## What it does

TRACE is a custom MCP server plus a self-correcting agent loop that makes an
incident-response agent unable to fabricate findings or damage evidence, and then
**measures** the result against ground truth.

- **Typed read-only tools.** Instead of `execute_shell`, the agent gets five
  typed functions (`get_amcache`, `extract_mft_timeline`, `analyze_prefetch`,
  `parse_evtx_logons`, `list_artifacts`). It physically cannot run a destructive
  command, because the server doesn't expose one.
- **Citations on every finding.** Each finding points to the exact line of raw
  tool output that produced it. A judge can trace any claim back to its source.
- **A verifier that catches hallucinations.** Any claim whose citation doesn't
  match real evidence is flagged `UNVERIFIED` and dropped.
- **Self-correction.** When the verifier drops claims, the loop re-runs with a
  tightened instruction, capped by `--max-iterations`.
- **A benchmark.** TRACE is scored against ground truth vs. an unverified
  baseline, reporting true positives, misses, false positives, and hallucination
  rate.

## How we built it

Pure-Python, zero external dependencies for the demo path, so judges can run it
in seconds. Evidence parsing lives behind a single read-only accessor
(`_read_lines`), which is the only code that touches disk. The MCP server
(`FastMCP`) advertises only the typed tools. The verifier re-reads the cited
bytes and compares them to the recorded `raw_line` - a fabricated or drifted
citation fails. Everything is logged to JSONL with timestamps and token usage.

## Challenges we ran into

- **Distinguishing fabrication from judgment.** The verifier should remove made-up
  facts, not legitimate analyst inference. We solved this with a `confidence`
  field - inferred findings are reported but labelled, while *uncited* claims are
  dropped entirely.
- **Proving the guardrail, not asserting it.** We made the shell-absence testable:
  asking the dispatch for a capability that doesn't exist raises, and we document
  that test in the accuracy report.
- **Making it runnable without the SIFT VM** so it could be built and benchmarked
  on day one, with a clean swap path to real parsers.

## What we learned

The defensible edge in agentic IR isn't a smarter prompt - prompts can be
ignored. It's *architecture*: constrain what the agent can do, and verify what it
claims against raw evidence. That's also exactly what the judging criteria reward
(constraint implementation, audit trail, accuracy).

## What's next

Swap the demo parsers for `regipy` / `python-evtx` / `analyzeMFT` / prefetch and
run on real SANS sample images; expand the typed toolset across more of SIFT's
200+ tools; add cross-artifact correlation (disk vs. memory discrepancy
detection) on top of the same citation/verifier contract.

## Built with

Python, Model Context Protocol (MCP / FastMCP), the SANS SIFT Workstation tool
ecosystem.

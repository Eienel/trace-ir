# TRACE - Accuracy Report

Case: `sample_data/case01`  •  Ground-truth malicious findings: **7**

## Results

| Mode | True positives | Missed | False positives | Hallucinations |
|---|---|---|---|---|
| Baseline (unverified, Protocol-SIFT-like) | 7 | 0 | 0 | 2 |
| TRACE (architectural verification) | 7 | 0 | 0 | 0 |

**Headline:** TRACE eliminated **2**
hallucinated claim(s) - from 2 to 0 -
while retaining all 7/7 true positives. TRACE converged
in 2 iteration(s) via self-correction.

## Evidence integrity

All parsing in `server/parsers.py` opens artifacts read-only; no code path
writes, moves, or deletes evidence. The MCP server exposes only typed analytical
functions - there is no `execute_shell`, `write_file`, or `delete`. Evidence
spoliation is therefore prevented **architecturally**, not by prompt instruction.
We tested this by attempting to invoke a shell capability through the agent loop;
the dispatch raises because no such tool exists (see `server.trace_server.call_tool`).

## Documented failure modes (signal, not weakness)

- Heuristic coverage in the demo parsers is intentionally small (location- and
  pattern-based). Real-evidence runs should swap in `regipy` / `python-evtx` /
  `analyzeMFT` / prefetch parsers - the citation/verifier contract is unchanged.
- The verifier confirms a finding is *grounded in tool output*; it does not
  certify the finding is *correct incident reasoning*. It removes fabrication,
  not analyst judgment.
- Inferred (vs. confirmed) findings are reported but labelled, so a human can
  weigh them appropriately.

## How to reproduce

```bash
python -m benchmark.make_sample_data
python -m benchmark.run_benchmark --case sample_data/case01
```

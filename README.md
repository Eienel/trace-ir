# TRACE - Typed Read-only Artifact Citation Engine

**A defensive AI agent for the SANS SIFT Workstation that cannot lie and proves it.**

Built for the SANS **FIND EVIL!** hackathon. TRACE addresses the stated problem
head-on: *"Protocol SIFT works. It also hallucinates more than we'd like."*

TRACE does not try to make the agent smarter with a better prompt. It removes the
agent's ability to fabricate or to damage evidence, **by architecture**, and then
**measures** the result.

## The thesis in one line

> Every finding is tied to a specific line of raw tool output. Any claim that
> isn't gets flagged `UNVERIFIED` and triggers a re-run. The agent physically
> cannot run a destructive command because the MCP server does not expose one.

This maps directly onto the judging criteria:

| Judging criterion | How TRACE addresses it |
|---|---|
| 1. Autonomous execution / self-correction | Verifier flags unsupported claims → loop re-runs with tightened scope, capped by `--max-iterations` |
| 2. IR accuracy | Findings carry evidence citations; benchmark scores hallucination + false-positive rate vs. baseline |
| 3. Breadth & depth | 5 typed forensic functions over registry/MFT/prefetch/EVTX artifacts |
| 4. Constraint implementation | **Architectural** guardrail: server exposes only read-only typed functions, no shell. Documented vs. prompt-based |
| 5. Audit trail | Every tool call logged to JSONL with timestamp + token usage; every finding traces to a raw line |
| 6. Usability & docs | Runs with `python`, zero external deps for the demo; clear upgrade path to real SIFT tools |

## Quick start (runs today, no SIFT VM needed)

```bash
# 1. Generate synthetic-but-realistic case artifacts
python -m benchmark.make_sample_data

# 2. Run the agent loop against the case (offline simulated agent)
python -m agent.loop --case sample_data/case01 --max-iterations 3

# 3. Score accuracy against ground truth
python -m benchmark.run_benchmark --case sample_data/case01

# 4. Inspect the audit trail
cat logs/execution_log.jsonl
```

Requires Python 3.10+. No pip installs needed for the demo path.

## Running the MCP server (for Claude Code / any MCP client)

```bash
python -m server.trace_server
```

Then point your MCP client (Claude Code, Cline, etc.) at it. See
`docs/ARCHITECTURE.md` for the tool contract.

## How this connects to the real SIFT Workstation

The demo ships synthetic artifacts so judges can run it instantly. To run against
real evidence on the SIFT Workstation, swap the parsers in `server/parsers.py` for
the real libraries (already stubbed and commented):

- `get_amcache()` → [`regipy`](https://github.com/mkorman90/regipy)
- `extract_mft_timeline()` → `analyzeMFT` / `mft`
- `analyze_prefetch()` → `prefetch` parser
- `parse_evtx_logons()` → [`python-evtx`](https://github.com/williballenthin/python-evtx)

The tool contract, citation model, verifier, and benchmark stay identical. Only the
parse functions change. This is deliberate: the architecture is the contribution.

## Live LLM run (real, unscripted hallucination test)

The deterministic demo uses a scripted over-reach so it runs with no API key. To
prove the verifier catches *real* model hallucinations, run a live agent. TRACE is
provider-agnostic and needs no SDK (stdlib `urllib` only) - set whichever key you
have:

```bash
export GEMINI_API_KEY=...        # or OPENAI_API_KEY / ANTHROPIC_API_KEY
#                                 # or LLM_API_KEY + LLM_API_BASE for any
#                                 # OpenAI-compatible endpoint (Groq, Together, Ollama...)

python -m agent.loop --case sample_data/case01 --live --max-iterations 3
python -m benchmark.run_benchmark --case sample_data/case01 --live
```

In live mode a real model reads the raw artifact lines and writes findings with
its own citations. The verifier re-reads each cited line: any claim the model
fabricates or mis-quotes fails and is dropped, and the agent re-runs told which
claims were rejected. The accuracy report records whether numbers came from a
live run or the deterministic demo.

## Repo layout

```
server/        Typed read-only MCP server + parsers + citation model
agent/         Verifier and self-correcting loop (the autonomy layer)
benchmark/     Ground-truth scoring harness + synthetic data generator
sample_data/   Generated case artifacts (after step 1)
logs/          Structured execution logs with timestamps + token usage
docs/          Architecture, accuracy report, dataset notes, diagram
```

## License

MIT - see `LICENSE`.

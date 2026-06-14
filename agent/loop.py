"""Self-correcting agent loop with full audit logging.

This models how a TRACE-governed agent behaves against a case:

  1. Plan: enumerate artifacts (list_artifacts).
  2. Analyze: call each typed read-only tool (or a real LLM in --live mode).
  3. Reason: the agent may add claims beyond raw output.
  4. VERIFY: every claim is checked against raw evidence. Unsupported claims are
     flagged UNVERIFIED and DROPPED from the report.
  5. Self-correct: if anything was dropped, re-run telling the agent which claims
     were rejected, up to --max-iterations.

Every step is written to logs/execution_log.jsonl with a timestamp and token
usage, so any finding traces back to the execution that produced it.

Two modes of evidence generation:
  - default (deterministic demo): typed tools produce cited findings, plus a
    scripted over-reach so the demo runs with no API key.
  - --live: a real LLM provider (Gemini/OpenAI/Anthropic/any OpenAI-compatible)
    reads the raw artifacts and writes findings; whatever it fabricates is caught
    by the verifier for real.

The `--mode baseline` flag disables the verifier to reproduce Protocol-SIFT-like
behaviour (claims pass through unverified) so the benchmark can measure the
before/after difference.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from typing import List

from server.citations import Finding
from server.trace_server import call_tool
from agent.verifier import verify_all

LOG_PATH = os.path.join("logs", "execution_log.jsonl")

ARTIFACT_TOOLS = {
    "amcache.txt": "get_amcache",
    "mft.txt": "extract_mft_timeline",
    "prefetch.txt": "analyze_prefetch",
    "evtx_logons.txt": "parse_evtx_logons",
}


def _log(event: dict) -> None:
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
    os.makedirs("logs", exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


def _est_tokens(findings: List[Finding]) -> int:
    """Rough token estimate for the audit trail (chars/4)."""
    return sum(len(f.summary) for f in findings) // 4 + 12 * len(findings)


def _inferred_claims(iteration: int) -> List[Finding]:
    """Scripted over-reach used by the deterministic demo (no API key path).

    On the first pass the stand-in agent volunteers two UNCITED claims (the kind
    of hallucination Protocol SIFT exhibits). It stops on later passes. In --live
    mode this is replaced by a real LLM and real, unscripted hallucinations.
    """
    if iteration == 0:
        return [
            Finding(
                id="inferred:exfil",
                summary="Data was exfiltrated to an external C2 server over HTTPS",
                severity="critical", confidence="inferred", citation=None),
            Finding(
                id="inferred:ransomware",
                summary="The intrusion is attributable to the LockBit affiliate group",
                severity="high", confidence="inferred", citation=None),
        ]
    return []


@dataclass
class IterationReport:
    iteration: int
    reported: List[Finding]
    dropped: List[Finding]


def run_case(case_dir: str, max_iterations: int, mode: str,
             live: bool = False) -> List[IterationReport]:
    history: List[IterationReport] = []
    _log({"event": "run_start", "case": case_dir, "mode": mode,
          "live": live, "max_iterations": max_iterations})

    rejected: List[str] = []  # claims the verifier dropped last pass (live self-correct)

    for it in range(max_iterations):
        findings: List[Finding] = []

        if live:
            # LIVE MODE: a real LLM reads the raw artifacts and writes findings
            # with its own claimed citations. Whatever it fabricates is caught by
            # the verifier for real - nothing is scripted.
            from agent.llm_agent import get_llm_findings
            findings = get_llm_findings(case_dir, it, rejected=rejected or None)
            _log({"event": "agent_call", "iteration": it, "agent": "llm",
                  "n_findings": len(findings), "est_tokens": _est_tokens(findings)})
        else:
            # DETERMINISTIC DEMO: typed tools produce cited findings; a scripted
            # over-reach stands in for the LLM so the demo runs with no API key.
            artifacts = call_tool("list_artifacts", case_dir=case_dir)
            _log({"event": "tool_call", "iteration": it, "tool": "list_artifacts",
                  "args": {"case_dir": case_dir}, "n_findings": len(artifacts),
                  "est_tokens": _est_tokens(artifacts)})
            for fname, tool in ARTIFACT_TOOLS.items():
                path = os.path.join(case_dir, fname)
                if not os.path.exists(path):
                    continue
                out = call_tool(tool, path=path)
                findings.extend(out)
                _log({"event": "tool_call", "iteration": it, "tool": tool,
                      "args": {"path": path}, "n_findings": len(out),
                      "est_tokens": _est_tokens(out)})
            findings.extend(_inferred_claims(it))

        # VERIFY (skipped in baseline mode to mimic unguarded Protocol SIFT).
        if mode == "trace":
            results = verify_all(findings)
            reported = [r.finding for r in results if r.verified]
            dropped = [r.finding for r in results if not r.verified]
            rejected = [f.summary for f in dropped]
            for r in results:
                _log({"event": "verification", "iteration": it,
                      "finding_id": r.finding.id, "verified": r.verified,
                      "reason": r.reason})
        else:  # baseline: everything passes through unchecked
            reported, dropped = findings, []

        history.append(IterationReport(it, reported, dropped))
        _log({"event": "iteration_summary", "iteration": it,
              "reported": len(reported), "dropped": len(dropped)})

        # Self-correct only if the verifier dropped something.
        if not dropped:
            _log({"event": "converged", "iteration": it})
            break

    _log({"event": "run_end", "case": case_dir})
    return history


def main() -> None:
    ap = argparse.ArgumentParser(description="TRACE self-correcting agent loop")
    ap.add_argument("--case", required=True, help="path to a case directory")
    ap.add_argument("--max-iterations", type=int, default=3)
    ap.add_argument("--mode", choices=["trace", "baseline"], default="trace")
    ap.add_argument("--live", action="store_true",
                    help="use a real LLM agent (any configured provider) instead "
                         "of the deterministic demo")
    args = ap.parse_args()

    live = args.live
    if live:
        from agent.llm_agent import llm_available, provider_name
        if not llm_available():
            print("No LLM provider configured (set GEMINI_API_KEY / OPENAI_API_KEY "
                  "/ ANTHROPIC_API_KEY / LLM_API_KEY). Falling back to demo mode.\n")
            live = False
        else:
            print(f"Live agent: {provider_name()}\n")

    history = run_case(args.case, args.max_iterations, args.mode, live=live)
    final = history[-1]

    tag = f"{args.mode}{', live' if live else ''}"
    print(f"\n=== TRACE report ({tag}) - case {args.case} ===")
    print(f"Iterations run: {len(history)}")
    print(f"Final reported findings: {len(final.reported)}")
    print(f"Claims dropped as UNVERIFIED across run: "
          f"{sum(len(h.dropped) for h in history)}\n")
    for f in final.reported:
        c = f.citation
        cite = (f"{c.source_tool}:{os.path.basename(c.source_file)}:L{c.line_number}"
                if c else "-")
        print(f"[{f.severity.upper():8}] {f.summary}")
        print(f"           evidence: {cite}")
    print(f"\nFull audit trail: {LOG_PATH}")


if __name__ == "__main__":
    main()

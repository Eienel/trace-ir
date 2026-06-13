"""The verifier - TRACE's anti-hallucination layer.

A finding is VERIFIED only if its citation points to a line that actually exists
in the cited artifact and matches the recorded raw text. Anything else is an
unverified claim: the agent asserting something the evidence does not support.

This is what lets a judge trace any finding back to the exact tool execution
that produced it (audit-trail criterion), and what catches hallucinations
(accuracy criterion).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List

from server.citations import Finding


@dataclass
class VerificationResult:
    finding: Finding
    verified: bool
    reason: str


def verify_finding(f: Finding) -> VerificationResult:
    c = f.citation
    if c is None:
        return VerificationResult(f, False, "no citation: unsupported claim")
    if c.line_number == 0:
        # Listing-type citation (e.g. list_artifacts) - verify the file exists.
        ok = os.path.exists(c.source_file)
        return VerificationResult(f, ok, "artifact exists" if ok else "artifact missing")
    if not os.path.exists(c.source_file):
        return VerificationResult(f, False, f"cited file does not exist: {c.source_file}")
    try:
        with open(c.source_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for ln in fh]
    except OSError as e:
        return VerificationResult(f, False, f"cited file unreadable: {e}")
    if c.line_number < 1 or c.line_number > len(lines):
        return VerificationResult(f, False, f"cited line {c.line_number} out of range")
    actual = lines[c.line_number - 1]
    if actual != c.raw_line:
        return VerificationResult(
            f, False,
            f"cited raw_line does not match line {c.line_number} (fabricated citation)")
    return VerificationResult(f, True, "citation matches raw evidence")


def verify_all(findings: List[Finding]) -> List[VerificationResult]:
    return [verify_finding(f) for f in findings]

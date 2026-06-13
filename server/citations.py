"""Evidence model for TRACE.

Every finding the agent is allowed to report MUST carry a Citation that points
to a specific line of raw tool output. A finding without a verifiable citation
is, by definition, an unverified claim and is treated as a potential
hallucination by the verifier.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Citation:
    """Pointer back to the exact raw evidence that produced a finding."""
    source_tool: str      # which typed function produced this (e.g. "get_amcache")
    source_file: str      # the artifact file the line came from
    line_number: int      # 1-based line number within that file
    raw_line: str         # the verbatim raw line of tool output

    def dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """A single analytical claim about the case."""
    id: str
    summary: str
    severity: str                       # info | low | medium | high | critical
    confidence: str                     # confirmed | inferred
    citation: Optional[Citation] = None  # None => unverifiable claim

    def dict(self) -> dict:
        d = asdict(self)
        return d

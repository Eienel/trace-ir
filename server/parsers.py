"""Read-only forensic parsers.

DESIGN INVARIANT: every function in this module opens artifacts in read-only
mode ('r') and NEVER writes, moves, or deletes evidence. There is no code path
here that mutates an input file. This is the architectural guardrail against
evidence spoliation - see docs/ARCHITECTURE.md.

For the hackathon demo these parse synthetic-but-realistic artifacts so judges
can run everything instantly. To run against REAL evidence on the SIFT
Workstation, replace the body of each function with the corresponding library
call (regipy / python-evtx / analyzeMFT / prefetch). The return contract -
a list[Finding] with a Citation per finding - does not change.
"""
from __future__ import annotations

import os
from typing import List

from .citations import Citation, Finding

SUSPICIOUS_DIRS = ("\\public\\", "\\temp\\", "\\appdata\\local\\temp\\", "\\programdata\\")
TYPOSQUAT_NAMES = ("svch0st", "scvhost", "lsas", "csrs", "rundl132", "explorerr")


def _read_lines(path: str) -> List[str]:
    """Read-only access to an artifact. The ONLY way this module touches disk."""
    # 'r' mode + no write methods called anywhere == evidence cannot be modified.
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [ln.rstrip("\n") for ln in fh]


def _is_suspicious_path(p: str) -> bool:
    lp = p.lower()
    if any(d in lp for d in SUSPICIOUS_DIRS):
        return True
    base = os.path.basename(lp)
    return any(t in base for t in TYPOSQUAT_NAMES)


# --------------------------------------------------------------------------- #
# Typed tool 1: AmCache - evidence of program execution
# --------------------------------------------------------------------------- #
def get_amcache(path: str) -> List[Finding]:
    """Parse AmCache execution records.  REAL: regipy.AmcacheParser."""
    findings: List[Finding] = []
    for i, line in enumerate(_read_lines(path), start=1):
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        exe_path, sha1, first_run = parts[0], parts[1], parts[2]
        if _is_suspicious_path(exe_path):
            findings.append(Finding(
                id=f"amcache:{i}",
                summary=f"Execution of binary from suspicious location: {exe_path} "
                        f"(SHA1 {sha1[:12]}…, first run {first_run})",
                severity="high",
                confidence="confirmed",
                citation=Citation("get_amcache", path, i, line),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Typed tool 2: MFT timeline - file system activity
# --------------------------------------------------------------------------- #
def extract_mft_timeline(path: str) -> List[Finding]:
    """Parse $MFT timeline rows.  REAL: analyzeMFT / mft."""
    findings: List[Finding] = []
    for i, line in enumerate(_read_lines(path), start=1):
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        ts, action, fpath = parts[0], parts[1].strip().upper(), parts[2]
        # Timestomping signal: $SI and $FN timestamps diverge (flagged in data),
        # or suspicious path with a creation event.
        if "TIMESTOMP" in action:
            findings.append(Finding(
                id=f"mft:{i}",
                summary=f"Possible timestomping on {fpath} at {ts} ($SI/$FN mismatch)",
                severity="high",
                confidence="inferred",
                citation=Citation("extract_mft_timeline", path, i, line),
            ))
        elif _is_suspicious_path(fpath) and action in ("CREATE", "BORN"):
            findings.append(Finding(
                id=f"mft:{i}",
                summary=f"File created in suspicious location: {fpath} at {ts}",
                severity="medium",
                confidence="confirmed",
                citation=Citation("extract_mft_timeline", path, i, line),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Typed tool 3: Prefetch - execution count and timing
# --------------------------------------------------------------------------- #
def analyze_prefetch(path: str) -> List[Finding]:
    """Parse prefetch records.  REAL: prefetch parser."""
    findings: List[Finding] = []
    for i, line in enumerate(_read_lines(path), start=1):
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        exe, run_count, last_run = parts[0], parts[1], parts[2]
        if _is_suspicious_path(exe):
            findings.append(Finding(
                id=f"prefetch:{i}",
                summary=f"Suspicious executable in prefetch: {exe} "
                        f"(run {run_count}x, last {last_run})",
                severity="high",
                confidence="confirmed",
                citation=Citation("analyze_prefetch", path, i, line),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Typed tool 4: EVTX logons - authentication activity
# --------------------------------------------------------------------------- #
def parse_evtx_logons(path: str) -> List[Finding]:
    """Parse security event-log logon records.  REAL: python-evtx + xmltodict."""
    findings: List[Finding] = []
    failures: dict[str, list[tuple[int, str]]] = {}
    for i, line in enumerate(_read_lines(path), start=1):
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 5:
            continue
        ts, event_id, account, src_ip, logon_type = (p.strip() for p in parts[:5])
        if event_id == "4625":  # failed logon - accumulate for brute-force detection
            failures.setdefault(src_ip, []).append((i, line))
        elif event_id == "4624" and logon_type == "10":  # RemoteInteractive (RDP)
            if not src_ip.startswith(("10.", "192.168.", "172.16.")):
                findings.append(Finding(
                    id=f"evtx:{i}",
                    summary=f"RDP logon (type 10) for {account} from EXTERNAL ip "
                            f"{src_ip} at {ts}",
                    severity="critical",
                    confidence="confirmed",
                    citation=Citation("parse_evtx_logons", path, i, line),
                ))
    # Brute force: >=5 failures from one source.
    for src_ip, hits in failures.items():
        if len(hits) >= 5:
            ln_no, raw = hits[0]
            findings.append(Finding(
                id=f"evtx:bruteforce:{src_ip}",
                summary=f"Brute-force pattern: {len(hits)} failed logons (4625) "
                        f"from {src_ip}",
                severity="high",
                confidence="inferred",
                citation=Citation("parse_evtx_logons", path, ln_no, raw),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Typed tool 5: enumerate available artifacts in a case (read-only listing)
# --------------------------------------------------------------------------- #
def list_artifacts(case_dir: str) -> List[Finding]:
    """List parseable artifacts present in a case directory (no analysis)."""
    findings: List[Finding] = []
    for name in sorted(os.listdir(case_dir)):
        full = os.path.join(case_dir, name)
        if os.path.isfile(full):
            findings.append(Finding(
                id=f"artifact:{name}",
                summary=f"Artifact present: {name}",
                severity="info",
                confidence="confirmed",
                citation=Citation("list_artifacts", full, 0, name),
            ))
    return findings


# Tool registry - the COMPLETE set of capabilities the agent has. There is no
# execute_shell, no write_file, no delete. The agent cannot do what isn't here.
TOOLS = {
    "list_artifacts": list_artifacts,
    "get_amcache": get_amcache,
    "extract_mft_timeline": extract_mft_timeline,
    "analyze_prefetch": analyze_prefetch,
    "parse_evtx_logons": parse_evtx_logons,
}

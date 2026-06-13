"""Real-evidence adapter: a genuine forensic library feeding TRACE.

This is the "Plan A" proof that TRACE's architecture is pluggable. It uses
`python-evtx` (the Evtx library) -- a real DFIR tool, the same one used on the
SIFT Workstation -- to read a REAL Windows Security event log (.evtx, a binary
forensic artifact) and normalize the logon events into the exact pipe-delimited
format the existing typed tool already understands.

Nothing in agent/, the verifier, the loop, or the benchmark changes. We only add
a real parser in front of the same citation contract. That is the whole point:
the architecture is the contribution; parsers are swappable.

Usage:
    pip install python-evtx --break-system-packages
    python3 -m server.real_tools <path-to.evtx> <output_dir>

It writes <output_dir>/evtx_logons.txt, which you then analyze with:
    python3 -m agent.loop --case <output_dir>
"""
from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
KEEP_EVENT_IDS = {"4624", "4625"}  # logon success / failure


def _text(node):
    return node.text if node is not None and node.text is not None else "-"


def evtx_to_normalized(evtx_path: str, out_dir: str) -> str:
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        raise SystemExit(
            "python-evtx is not installed. Run:\n"
            "  pip install python-evtx --break-system-packages")

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "evtx_logons.txt")

    rows = ["# timestamp|event_id|account|src_ip|logon_type  (from real .evtx via python-evtx)"]
    kept = 0
    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            sysblk = root.find("e:System", NS)
            if sysblk is None:
                continue
            eid = _text(sysblk.find("e:EventID", NS))
            if eid not in KEEP_EVENT_IDS:
                continue
            tc = sysblk.find("e:TimeCreated", NS)
            ts = tc.attrib.get("SystemTime", "-") if tc is not None else "-"
            data = {}
            edata = root.find("e:EventData", NS)
            if edata is not None:
                for d in edata.findall("e:Data", NS):
                    data[d.attrib.get("Name", "")] = d.text or "-"
            account = data.get("TargetUserName", "-")
            ip = data.get("IpAddress", "-")
            logon_type = data.get("LogonType", "-")
            rows.append(f"{ts}|{eid}|{account}|{ip}|{logon_type}")
            kept += 1

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rows) + "\n")

    print(f"Read real artifact: {evtx_path}")
    print(f"Parsed with python-evtx, kept {kept} logon events (4624/4625)")
    print(f"Wrote normalized artifact: {out_path}")
    print("\nNow analyze it with TRACE (same pipeline, unchanged):")
    print(f"  python3 -m agent.loop --case {out_dir}")
    return out_path


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: python3 -m server.real_tools <path-to.evtx> <output_dir>")
        raise SystemExit(2)
    evtx_to_normalized(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()

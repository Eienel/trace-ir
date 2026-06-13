"""Generate a synthetic-but-realistic case for instant, dependency-free testing.

The artifacts mimic the *shape* of real DFIR output (AmCache, $MFT, prefetch,
EVTX logons) so the full pipeline - typed tools, citations, verifier, benchmark -
runs end to end without the SIFT VM. Ground truth is written alongside so the
benchmark can score accuracy objectively.

On the SIFT Workstation, point the agent at real artifacts instead; the ground
truth here is only for the offline benchmark.
"""
from __future__ import annotations

import json
import os

CASE = os.path.join("sample_data", "case01")

AMCACHE = """# execution_path|sha1|first_run_time
C:\\Windows\\System32\\notepad.exe|a1b2c3d4e5f6a1b2c3d4|2026-05-01T09:14:00
C:\\Users\\Public\\svch0st.exe|deadbeefdeadbeefdead|2026-06-10T02:10:55
C:\\Program Files\\Acme\\acme.exe|0011223344556677aabb|2026-04-20T11:02:31
C:\\Users\\victim\\AppData\\Local\\Temp\\update.exe|f00df00df00dcafef00d|2026-06-10T02:09:40
"""

MFT = """# timestamp|action|path
2026-06-10T02:10:50|CREATE|C:\\Users\\Public\\svch0st.exe
2026-06-10T02:12:03|TIMESTOMP|C:\\Users\\Public\\svch0st.exe
2026-05-01T09:00:00|MODIFY|C:\\Users\\victim\\Documents\\report.docx
"""

PREFETCH = """# exe|run_count|last_run
C:\\Users\\Public\\svch0st.exe|7|2026-06-10T02:15:11
C:\\Windows\\System32\\cmd.exe|3|2026-06-09T18:44:02
"""

EVTX = """# timestamp|event_id|account|src_ip|logon_type
2026-06-10T02:00:01|4625|administrator|203.0.113.45|3
2026-06-10T02:00:05|4625|administrator|203.0.113.45|3
2026-06-10T02:00:09|4625|administrator|203.0.113.45|3
2026-06-10T02:00:14|4625|administrator|203.0.113.45|3
2026-06-10T02:00:20|4625|administrator|203.0.113.45|3
2026-06-10T02:01:30|4624|administrator|203.0.113.45|10
2026-06-10T08:30:00|4624|victim|192.168.1.20|2
"""

# Ground truth - the finding IDs a correct analysis MUST surface (and nothing
# fabricated beyond them). IDs match what the typed tools emit (tool:line_no).
GROUND_TRUTH = [
    "amcache:3",                       # svch0st.exe from \Public
    "amcache:5",                       # update.exe from \AppData\Local\Temp
    "mft:2",                           # svch0st.exe created in \Public
    "mft:3",                           # timestomping on svch0st.exe
    "prefetch:2",                      # svch0st.exe executed 7x
    "evtx:7",                          # external RDP (type 10) logon
    "evtx:bruteforce:203.0.113.45",    # 5x failed logons
]


def main() -> None:
    os.makedirs(CASE, exist_ok=True)
    files = {
        "amcache.txt": AMCACHE,
        "mft.txt": MFT,
        "prefetch.txt": PREFETCH,
        "evtx_logons.txt": EVTX,
    }
    for name, content in files.items():
        with open(os.path.join(CASE, name), "w", encoding="utf-8") as fh:
            fh.write(content)
    with open(os.path.join(CASE, "ground_truth.json"), "w", encoding="utf-8") as fh:
        json.dump({"true_findings": GROUND_TRUTH}, fh, indent=2)

    print(f"Wrote case to {CASE}/")
    for name in files:
        print(f"  - {name}")
    print(f"  - ground_truth.json ({len(GROUND_TRUTH)} true findings)")


if __name__ == "__main__":
    main()

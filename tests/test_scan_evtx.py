#!/usr/bin/env python3
"""Manual smoke test: calls the scan_evtx tool directly against a sample EVTX file.

Sample source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
(Credential Access/CA_DCSync_4662.evtx, saved under tests/samples/)
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server

SAMPLE_EVTX = Path(__file__).resolve().parent / "samples" / "CA_DCSync_4662.evtx"


async def run() -> None:
    print(f"Scanning {SAMPLE_EVTX} ...\n")
    result = await server.call_tool(
        "scan_evtx",
        {"evtx_path": str(SAMPLE_EVTX), "min_severity": "low"},
    )
    print(result[0].text)


if __name__ == "__main__":
    asyncio.run(run())

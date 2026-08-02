#!/usr/bin/env python3
"""Download the MITRE ATT&CK Enterprise STIX bundle to ./attack_data/"""

import shutil
import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
DEST_DIR = Path(__file__).resolve().parent.parent / "attack_data"
DEST_FILE = DEST_DIR / "enterprise-attack.json"


def main() -> None:
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {URL}...")
    with urllib.request.urlopen(URL) as resp, open(DEST_FILE, "wb") as f:
        shutil.copyfileobj(resp, f)
    print(f"Done. ATT&CK data saved to {DEST_FILE}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

"""Recall and false-positive rate on deepset/prompt-injections (Apache-2.0), full lane.

The dataset is fetched at run time from the Hugging Face rows API and is not vendored. Each
row is screened as untrusted text (`scan_text`, every detector); a row counts as flagged when
the screen reports any finding. Train and test splits are reported separately: the phrase
variants added after the first run were written from the TRAIN split only, so the TEST split
is the held-out number.

    python benchmarks/run_deepset.py            # needs network access; standard library only

The rows API is not pinned to a dataset revision; the row counts printed first (546 train,
116 test when this was measured) show whether the dataset changed.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from injection_screen.detectors import scan_text

API = ("https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections"
       "&config=default&split={split}&offset={offset}&length=100")


def fetch(split: str) -> list[dict]:
    rows: list[dict] = []
    while True:
        url = API.format(split=split, offset=len(rows))
        for attempt in range(8):
            try:
                with urllib.request.urlopen(url, timeout=60) as r:
                    page = json.load(r)
                break
            except urllib.error.HTTPError as e:
                if e.code != 429 or attempt == 7:
                    raise
                time.sleep(3 * (attempt + 1))
        got = [x["row"] for x in page.get("rows", [])]
        rows += got
        if len(got) < 100:
            return rows
        time.sleep(1.5)


def main() -> int:
    for split in ("train", "test"):
        rows = fetch(split)
        tp = fn = fp = tn = 0
        for row in rows:
            hit = bool(scan_text(row["text"], Path("row.txt")))
            if row["label"] == 1:
                tp, fn = tp + hit, fn + (not hit)
            else:
                fp, tn = fp + hit, tn + (not hit)
        print(f"{split}: {len(rows)} rows | injections flagged {tp}/{tp + fn} "
              f"({tp / max(tp + fn, 1):.1%}) | benign flagged {fp}/{fp + tn} ({fp / max(fp + tn, 1):.1%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

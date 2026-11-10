"""Recall and false alarms on public prompt-injection datasets, patterns and optional judge reported
separately. Datasets are fetched from the Hugging Face rows API at run time and not vendored; network
needed, standard library only. The rows API is not pinned to a revision: the row counts printed show
whether a dataset changed.

    python benchmarks/run_heldout.py                          # patterns only
    python benchmarks/run_heldout.py --judge MODEL --sample 150   # also ask a local Ollama model

The judge sends each sampled row to `--judge-url` (default: this machine). Judge numbers belong to
that model and can vary between runs.
"""
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from injection_screen import judge
from injection_screen.detectors import scan_text

API = "https://datasets-server.huggingface.co/rows?dataset={d}&config=default&split={s}&offset={o}&length=100"
#: name, dataset, split, text column, how to read the label, most rows to fetch (None = all)
SOURCES = [
    ("xTRam1 train", "xTRam1/safe-guard-prompt-injection", "train", "text", lambda r: r["label"], None),
    ("xTRam1 test", "xTRam1/safe-guard-prompt-injection", "test", "text", lambda r: r["label"], None),
    ("geekyrakshit test", "geekyrakshit/prompt-injection-dataset", "test", "prompt", lambda r: int(r["label"]), 3000),
    ("jackhhao test", "jackhhao/jailbreak-classification", "test", "prompt", lambda r: int(r["type"] == "jailbreak"), None),
    ("Gandalf test", "Lakera/gandalf_ignore_instructions", "test", "text", lambda r: 1, None),
    ("deepset test", "deepset/prompt-injections", "test", "text", lambda r: r["label"], None),
]


def page(dataset: str, split: str, offset: int) -> dict:
    url = API.format(d=urllib.parse.quote(dataset, safe=""), s=split, o=offset)
    for attempt in range(8):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503) or attempt == 7:
                raise
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("unreachable")


def fetch(dataset: str, split: str, limit: int | None) -> tuple[list[dict], int]:
    first = page(dataset, split, 0)
    total = first["num_rows_total"]
    offsets = list(range(0, total, 100))
    if limit is not None and total > limit:
        random.Random(7).shuffle(offsets)
        offsets = offsets[:limit // 100]
    rows: list[dict] = []
    for o in offsets:
        rows += [x["row"] for x in page(dataset, split, o)["rows"]]
        time.sleep(0.5)
    return rows, total


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--judge", metavar="MODEL")
    ap.add_argument("--judge-url", default=judge.DEFAULT_URL)
    ap.add_argument("--sample", type=int, default=150, help="rows per side the model reads (default: %(default)s)")
    a = ap.parse_args()
    for name, dataset, split, col, label, limit in SOURCES:
        rows, total = fetch(dataset, split, limit)
        print(f"{name}: {len(rows)} of {total} rows")
        for side, want in (("attacks", 1), ("benign", 0)):
            texts = [r[col] for r in rows if label(r) == want and r[col]]
            if not texts:
                continue
            hit = sum(bool(scan_text(t, Path("row.txt"))) for t in texts)
            print(f"  patterns {side}: {hit}/{len(texts)} = {hit / len(texts):.1%}")
            if a.judge:
                random.Random(11).shuffle(texts)
                part = texts[:a.sample]
                said = failed = 0
                for t in part:
                    try:
                        said += judge.ask(t[:judge.WINDOW_CHARS], a.judge, a.judge_url)
                    except judge.JudgeError:
                        failed += 1
                done = len(part) - failed
                print(f"  {a.judge} {side}: {said}/{done} = {said / max(done, 1):.1%}"
                      + (f" ({failed} not answered)" if failed else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

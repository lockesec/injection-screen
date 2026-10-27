"""Every public benchmark in one run, with a denominator on every row.

    python benchmarks/run_all.py                      # print the table
    python benchmarks/run_all.py --write              # also rewrite docs/benchmark-results.md
    python benchmarks/run_all.py --benign DIR [DIR]   # add your own benign folders

Needs network access; standard library only. Each corpus is fetched at run time and not
vendored: InjecAgent and Trail of Bits' overtly-malicious-skills as GitHub tarballs pinned to a
commit, deepset/prompt-injections from the Hugging Face rows API (not pinned; its row counts
are printed so a change shows). Nothing fetched is executed: the screen only reads it.

Rows:
* deepset/prompt-injections train and test (full lane, each row as text). The phrase variants
  were written from the TRAIN split; TEST is the held-out number.
* InjecAgent (MIT) base and enhanced cases, direct harm and data stealing: the tool response
  that carries the attacker instruction, screened as a tool result. "enhanced" cases all share
  one fixed "IMPORTANT!!! Ignore all previous instructions" prefix, so that row measures one
  phrase, not breadth. The benign row is each distinct tool-response template with a benign
  review in place of the attacker instruction.
* Trail of Bits overtly-malicious-skills: each skill directory screened in the full lane and in
  the skill lane (`claude-surface`), counted as caught on exit 1.
* --benign DIR: files flagged / files scanned, full lane (every detector).
"""
from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from run_deepset import fetch as fetch_deepset  # noqa: E402

from injection_screen.detectors import scan_text  # noqa: E402

INJECAGENT = ("uiuc-kang-lab/InjecAgent", "f19c9f2c79a41046eb13c03c51a24c567a8ffa07")
TRAILOFBITS = ("trailofbits/overtly-malicious-skills", "4ffbf9461ef0505f9ce76a0d3694a18ec33ea531")


def tarball(repo: str, ref: str, into: Path) -> Path:
    """Download a GitHub tarball at a commit and extract it safely (no absolute paths, no
    `..`, no links or devices). Returns the extracted top directory."""
    url = f"https://codeload.github.com/{repo}/tar.gz/{ref}"
    with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310 (fixed https URL)
        data = r.read()
    return extract(data, into)


def extract(data: bytes, into: Path) -> Path:
    """Extract a gzipped tarball, skipping absolute paths, `..`, links and devices."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        top = None
        for m in tf.getmembers():
            p = Path(m.name)
            if p.is_absolute() or ".." in p.parts or not (m.isfile() or m.isdir()):
                continue
            top = top or p.parts[0]
            tf.extract(m, into)
    return into / top


def row(name: str, hit: int, total: int, note: str = "") -> dict:
    return {"source": name, "flagged": hit, "total": total,
            "rate": f"{hit / total:.1%}" if total else "n/a", "note": note}


def deepset_rows() -> list[dict]:
    out = []
    for split in ("train", "test"):
        rows = fetch_deepset(split)
        inj = [r for r in rows if r["label"] == 1]
        ben = [r for r in rows if r["label"] == 0]
        hit = sum(1 for r in inj if scan_text(r["text"], Path("row.txt")))
        fp = sum(1 for r in ben if scan_text(r["text"], Path("row.txt")))
        held = "held out" if split == "test" else "variants written from this split"
        out.append(row(f"deepset {split}: injections", hit, len(inj), held))
        out.append(row(f"deepset {split}: benign", fp, len(ben), "false positives"))
    return out


def injecagent_rows(tmp: Path) -> list[dict]:
    root = tarball(*INJECAGENT, tmp)
    out = []
    templates = set()
    for kind, label in (("dh", "direct harm"), ("ds", "data stealing")):
        for variant in ("base", "enhanced"):
            cases = json.loads((root / "data" / f"test_cases_{kind}_{variant}.json").read_text())
            hit = sum(1 for c in cases if scan_text(c["Tool Response"], Path("tool-result")))
            note = ("one shared override prefix" if variant == "enhanced"
                    else "plain requests, no injection wording")
            out.append(row(f"InjecAgent {label}, {variant}", hit, len(cases), note))
            templates.update(c["Tool Response Template"] for c in cases)
    fp = sum(1 for t in templates if scan_text(
        t.replace("<Attacker Instruction>", "Great product, works as described."), Path("tool-result")))
    out.append(row("InjecAgent tool-response templates, benign", fp, len(templates), "false positives"))
    return out


def trailofbits_rows(tmp: Path) -> list[dict]:
    root = tarball(*TRAILOFBITS, tmp)
    skills = sorted(p for p in (root / "skills").iterdir() if p.is_dir())
    out = []
    for lane in ("untrusted-web", "claude-surface"):
        hit = 0
        for s in skills:
            r = subprocess.run([sys.executable, "-m", "injection_screen", str(s), "--provenance",
                                lane, "--no-session"], capture_output=True, timeout=600)
            hit += r.returncode == 1
        out.append(row(f"Trail of Bits skills, {lane} lane", hit, len(skills),
                       "detectors written after studying this corpus: a regression check"))
    return out


def benign_rows(dirs: list[Path]) -> list[dict]:
    from injection_screen import surfaces
    out = []
    for d in dirs:
        en = surfaces.collect([d])
        hit = 0
        for f in en.files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            hit += bool(scan_text(text, f))
        out.append(row(f"benign: {d.name}/", hit, len(en.files), "false positives, files"))
    return out


def table(rows: list[dict]) -> str:
    lines = ["| Source | Flagged | Of | Rate | Note |", "|---|---|---|---|---|"]
    lines += [f"| {r['source']} | {r['flagged']} | {r['total']} | {r['rate']} | {r['note']} |"
              for r in rows]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--write", action="store_true", help="rewrite docs/benchmark-results.md")
    ap.add_argument("--benign", nargs="*", type=Path, default=[], help="your own benign folders")
    a = ap.parse_args()
    rows: list[dict] = []
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for part in (lambda: deepset_rows(), lambda: injecagent_rows(tmp),
                     lambda: trailofbits_rows(tmp), lambda: benign_rows(a.benign)):
            rows += part()
    out = table(rows)
    print(out)
    if a.write:
        from injection_screen import __version__
        doc = HERE.parent / "docs" / "benchmark-results.md"
        doc.write_text(
            "# Benchmark results\n\nGenerated by `python benchmarks/run_all.py --write` "
            f"(injection-screen {__version__}); do not edit by hand. Corpora: InjecAgent at "
            f"`{INJECAGENT[1][:7]}`, Trail of Bits at `{TRAILOFBITS[1][:7]}`, deepset from the "
            "Hugging Face rows API. How to read each row: "
            "[measured-recall.md](measured-recall.md).\n\n" + out + "\n", encoding="utf-8")
        print(f"wrote {doc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

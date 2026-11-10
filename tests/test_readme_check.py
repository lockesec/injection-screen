"""examples/check_readme.py: a README transcript line the tool does not print is caught,
the README quick start matches the real output, and the project's own docs pass
their own smuggling screen."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from injection_screen import pipeline, surfaces

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("_check_readme", ROOT / "examples" / "check_readme.py")
chk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chk)

OUT = ["$ tool a", "HIGH   x  y", "DROPPED a: gone", "NOT EVALUABLE: nothing", "(exit 2)"]


def test_matching_transcript_has_no_problems():
    assert chk.problems(OUT, [], "", OUT) == []


def test_a_collapsed_line_is_caught():
    bad = ["$ tool a", "HIGH x y", "(exit 2)"]
    assert any("HIGH x y" in p for p in chk.problems(bad, [], "", OUT))


def test_an_omitted_line_the_tool_prints_is_not_checked_but_a_wrong_order_is():
    swapped = ["$ tool a", "NOT EVALUABLE: nothing", "DROPPED a: gone"]
    assert chk.problems(swapped, [], "", OUT)


def test_only_a_trailing_marker_elides_and_only_the_tail():
    assert chk.problems(["HIGH   x ..."], [], "", OUT) == []
    assert chk.problems(["HIGH   z ..."], [], "", OUT)
    assert chk.problems(["HIGH ... x  y"], [], "", OUT)


def test_setup_line_must_be_in_the_demo_script():
    assert chk.problems(["$ tool a"], ["mkdir web"], "mkdir web\n", OUT) == []
    assert chk.problems(["$ tool a"], ["mkdir other"], "mkdir web\n", OUT)


def test_the_real_readme_has_a_transcript_and_setup():
    transcript, setup = chk.quick_start_blocks((ROOT / "README.md").read_text())
    assert transcript[0].startswith("$ injection-screen") and setup
    assert chk.problems([], setup, (ROOT / "examples" / "demo.sh").read_text(), []) == []


def test_a_readme_without_a_transcript_cannot_be_checked():
    with pytest.raises(ValueError):
        chk.quick_start_blocks("# x\n\n## Quick start\n\nnothing\n\n## Next\n")


# ------------------------------------------------------------ README quick start

def test_readme_quick_start_matches_the_real_output():
    """Runs examples/check_readme.py as CI does, with this interpreter's scripts dir
    on PATH so `injection-screen` is the one under test."""
    import os
    exe = Path(sys.executable).parent
    if not (exe / "injection-screen").exists():
        pytest.skip("injection-screen console script is not installed in this venv")
    env = dict(os.environ, PATH=f"{exe}{os.pathsep}{os.environ['PATH']}")
    p = subprocess.run([sys.executable, str(ROOT / "examples" / "check_readme.py")],
                       env=env, capture_output=True, text=True, timeout=180)
    assert p.returncode == 0, p.stderr[-800:]


# ------------------------------------------------------------ the project's own docs

def test_the_projects_own_docs_pass_their_own_smuggling_screen():
    """README, docs, CHANGELOG, DESIGN and friends are screened by CI under
    repo-internal with the committed ack file. Quoted attack strings in them are
    acknowledged by fingerprint, none unacknowledged."""
    paths = [ROOT / p for p in ("README.md", "CHANGELOG.md", "DESIGN.md", "CONTRIBUTING.md",
                                "SECURITY.md", "docs", "examples")]
    en = surfaces.collect(paths)
    res = pipeline.run(en.files, "repo-internal", root=ROOT, scan_dirs=en.scan_dirs, session=False)
    assert not res["findings"], res["findings"][:3]
    assert res["scanned"] >= 8


def test_the_doc_claim_about_other_hidden_text_is_gone():
    d = (ROOT / "docs" / "detectors.md").read_text(encoding="utf-8")
    assert "which the other detectors in the lane cover" not in d
    assert "keeps HTML parsers and lexers quiet" not in d
    assert "evil.com" not in d

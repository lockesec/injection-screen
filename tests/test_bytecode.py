"""Unchecked hash-based bytecode that runs instead of its reviewed source is
flagged in every lane; ordinary and stale caches are not, and a directory of
only bytecode is screened rather than reported as not evaluable."""
from __future__ import annotations

import io
import json
import os
import py_compile
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from injection_screen import cli


def run(*argv: str) -> tuple[int, dict]:
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        rc = cli.main([*argv, "--no-session", "--json"])
    return rc, json.loads(out.getvalue()) if out.getvalue() else {}


def write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ------------------------------------------------------------ hash-based and sourceless bytecode

def _module(d: Path, body: str = "X = 1\n") -> Path:
    src = d / "mod.py"
    src.write_text(body)
    return src


def test_unchecked_hash_bytecode_is_flagged_in_every_lane(tmp_path):
    src = _module(tmp_path)
    py_compile.compile(str(src), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    for prov in ("untrusted-web", "claude-surface"):
        rc, res = run(str(tmp_path), "--provenance", prov)
        assert rc == 1, prov
        assert [x["kind"] for x in res["findings"]] == ["bytecode-mismatch"], prov
        assert "unchecked hash-based" in res["findings"][0]["excerpt"]


@pytest.mark.parametrize("mode", [py_compile.PycInvalidationMode.TIMESTAMP,
                                  py_compile.PycInvalidationMode.CHECKED_HASH])
def test_an_ordinary_cache_is_not_flagged(tmp_path, mode):
    src = _module(tmp_path)
    py_compile.compile(str(src), invalidation_mode=mode)
    rc, res = run(str(tmp_path), "--provenance", "untrusted-web")
    assert rc == 0 and res["findings"] == []


def test_a_stale_cache_is_not_flagged_python_recompiles_it(tmp_path):
    src = _module(tmp_path)
    py_compile.compile(str(src))
    src.write_text("X = 2  # edited after the cache was written\n")
    os.utime(src, (time.time() + 10, time.time() + 10))
    rc, res = run(str(tmp_path), "--provenance", "untrusted-web")
    assert rc == 0 and res["findings"] == []


def test_importable_sourceless_bytecode_is_flagged(tmp_path):
    src = _module(tmp_path)
    py_compile.compile(str(src), cfile=str(tmp_path / "mod.pyc"))
    src.unlink()
    rc, res = run(str(tmp_path), "--provenance", "claude-surface")
    assert rc == 1
    assert "no source" in res["findings"][0]["excerpt"]


def test_a_directory_of_only_bytecode_is_screened_not_unevaluable(tmp_path):
    src = _module(tmp_path)
    py_compile.compile(str(src), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    src.rename(tmp_path / "mod.txt.bak")          # leave only the cache in the walk
    rc, _ = run(str(tmp_path / "__pycache__"), "--provenance", "untrusted-web")
    assert rc == 1


def test_bytecode_only_run_counts_the_checked_headers(tmp_path, capsys):
    import py_compile
    src = write(tmp_path / "elsewhere" / "m.py", "x = 1\n")
    pyc = tmp_path / "tree" / "__pycache__" / "m.pyc"
    pyc.parent.mkdir(parents=True)
    py_compile.compile(str(src), cfile=str(pyc))
    tree = str(tmp_path / "tree")
    rc = cli.main([tree, "--provenance", "repo-internal", "--no-session", "--json"])
    res = json.loads(capsys.readouterr().out)
    assert rc == 0 and res["scanned"] == 0 and res["bytecode_checked"] == 1
    cli.main([tree, "--provenance", "repo-internal", "--no-session"])
    assert "bytecode_checked=1" in capsys.readouterr().out

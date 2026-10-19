"""The benchmark harness, offline: its archive extraction refuses unsafe members, and its table
prints a denominator on every row."""
import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
import run_all  # noqa: E402


def tgz(members: dict, links=()) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in members.items():
            data = text.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for name, target in links:
            ti = tarfile.TarInfo(name)
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            tf.addfile(ti)
    return buf.getvalue()


def test_extract_skips_traversal_absolute_paths_and_links(tmp_path):
    data = tgz({"repo-abc/data/ok.json": "{}", "../escape.txt": "x", "/abs.txt": "x"},
               links=[("repo-abc/link", "/etc/passwd")])
    top = run_all.extract(data, tmp_path / "out")
    assert (top / "data" / "ok.json").is_file()
    assert not (tmp_path / "escape.txt").exists() and not (top / "link").exists()
    assert not Path("/abs.txt").exists() or Path("/abs.txt").stat().st_size != 1


def test_every_row_prints_its_denominator():
    out = run_all.table([run_all.row("x", 3, 10, "n"), run_all.row("empty", 0, 0)])
    assert "| x | 3 | 10 | 30.0% | n |" in out and "| empty | 0 | 0 | n/a |" in out

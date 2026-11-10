"""--provenance names where PATHS came from. With --preset or --memory the lane is fixed, so
the flag is refused instead of being silently ignored."""
import pytest

from injection_screen import cli


@pytest.mark.parametrize("mode", [["--preset", "claude-code"], ["--memory"]])
def test_provenance_with_a_preset_or_memory_is_a_usage_error(tmp_path, capsys, mode):
    code = cli.main([*mode, "--root", str(tmp_path), "--claude-home", str(tmp_path),
                     "--provenance", "untrusted-web", "--no-session"])
    assert code == 64
    assert "--provenance" in capsys.readouterr().err

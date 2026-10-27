"""Tests run against the source tree (src/ layout) without an install; CI also
runs them against the installed wheel."""
import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


#: Wall-clock bounds in the tests guard against super-linear blowups (hours per MB), not speed.
#: Shared CI runners measured 1.03 s and 5.2 s against 1.0 s and 5.0 s bounds, so CI sets
#: INJECTION_SCREEN_TIME_SCALE=3; locally the bounds stay as written.
TIME_SCALE = float(os.environ.get("INJECTION_SCREEN_TIME_SCALE", "1"))


def _installed() -> bool:
    """True when `injection_screen` imports in a fresh interpreter that keeps only absolute
    sys.path entries: the way the installed hook command runs (it drops the project directory
    so a shadow package there cannot run instead)."""
    import subprocess
    prog = ("import os,sys;sys.path[:]=[p for p in sys.path if p and os.path.isabs(p)];"
            "import injection_screen")
    return subprocess.run([sys.executable, "-c", prog], capture_output=True,
                          cwd="/").returncode == 0


#: Tests of the INSTALLED hook command. CI runs them in its clean-install step; from a source
#: tree without an install they skip, saying why (they are never silently unrun in CI).
INSTALLED = _installed()
if os.environ.get("INJECTION_SCREEN_REQUIRE_INSTALLED") and not INSTALLED:
    raise RuntimeError("INJECTION_SCREEN_REQUIRE_INSTALLED is set but the package does not import "
                       "from a clean sys.path: the installed-command tests would skip, not run")

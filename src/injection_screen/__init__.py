"""injection-screen: a provenance-aware first screen for prompt injection in content
entering an AI agent's trusted context (tool output, fetched web pages, memory files,
instruction surfaces). Offline, deterministic, standard library only."""
from __future__ import annotations

__version__ = "0.1.0"

from .detectors import scan_file, scan_text  # noqa: E402
from .pipeline import run  # noqa: E402

__all__ = ["__version__", "run", "scan_file", "scan_text"]

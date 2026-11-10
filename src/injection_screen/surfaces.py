"""Surfaces: what to scan, and with which provenance.

A *preset* names a set of directories under a project root plus the provenance
they carry. Two ship built in:

claude-code
    The Claude Code instruction surface of a project: `CLAUDE.md`,
    `CLAUDE.local.md`, `.claude/CLAUDE.md`, `AGENTS.md`, and the `.claude/`
    directories `skills`, `agents`, `commands`, `plugins`, `rules` and
    `output-styles`. These files load into the agent's context, so they are
    scanned under the `claude-surface` lane: hidden payloads only, because
    skills and defense notes legitimately quote attack phrases.
claude-memory
    Claude Code's auto-memory directories (`~/.claude/projects/*/memory`).
    Memory is read back as trusted context by every future session, so a
    single poisoned row persists an attack: the MINJA class. This is scanned
    under the full lane.

Enumeration never skips silently. Everything a walk could not look at comes
back with a reason (an unreadable directory, a special file, a broken link),
and the caller turns that into a PARTIAL run. Symlinked directories are
followed, once each by real path, so a loop ends instead of recursing. An
ABSENT preset root is information, not a gap (there is nothing there to scan);
a preset whose roots are all absent has not been scanned clean. It has not
been scanned.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from . import detectors

#: Suffixes a DIRECTORY WALK reads, compared case-insensitively. A file named
#: explicitly on the command line is read whatever its suffix.
#: Scripts are read too: a skill's payload is as likely to sit in the script it
#: tells the agent to run as in its prose (only the smuggling-class detectors
#: and the full lane's phrase detectors apply, as for any file).
#: So is every text-like format an agent is handed and a renderer shows: Markdown
#: dialects, reStructuredText, AsciiDoc, HTML, XML and SVG, notebooks, and the
#: structured data and config formats. A suffix left out is a file a walk passes over
#: at exit 0, which is why the list is wide; what is still passed over is COUNTED
#: (`skipped_by_suffix`) and printed in the SUMMARY line.
SCRIPT_SUFFIXES = (".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
                   ".rb", ".pl", ".ps1")
PROSE_SUFFIXES = (".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc", ".asciidoc",
                  ".html", ".htm", ".xhtml", ".xml", ".svg", ".ipynb")
DATA_SUFFIXES = (".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".cfg")
TEXT_SUFFIXES = PROSE_SUFFIXES + DATA_SUFFIXES + SCRIPT_SUFFIXES
#: Configuration and build files read by name whatever their suffix: package-registry
#: settings (where a registry redirect is planted), files that run commands at build or
#: setup time, and environment and shell profiles. `Dockerfile.<x>` and `.env.<x>` are
#: read too, unless `<x>` is an image or archive suffix.
NAMED_FILES = frozenset({
    ".npmrc", ".yarnrc", ".pypirc", "pip.conf", ".condarc",
    "dockerfile", "containerfile", "makefile", "gnumakefile", "jenkinsfile", "procfile",
    "justfile", ".env", ".envrc", ".bashrc", ".zshrc", ".profile", ".bash_profile",
})
_NAMED_PREFIXES = ("dockerfile.", ".env.")
_NOT_TEXT = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".zip", ".gz",
                       ".tar", ".tgz", ".7z", ".pdf"})


def named_file(name: str) -> bool:
    """Whether a walk reads ``name`` by name (case-insensitive) whatever its suffix."""
    low = name.lower()
    if low in NAMED_FILES:
        return True
    return (low.startswith(_NAMED_PREFIXES)
            and os.path.splitext(low)[1] not in _NOT_TEXT)
INSTRUCTION_SUFFIXES = TEXT_SUFFIXES

PRESETS: dict[str, tuple[str, list[str]]] = {
    # name -> (provenance, roots relative to the project root; files or dirs)
    "claude-code": ("claude-surface",
                    ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".claude/CLAUDE.md",
                     ".claude/skills", ".claude/agents", ".claude/commands",
                     ".claude/plugins", ".claude/rules", ".claude/output-styles"]),
}


@dataclass
class Enumeration:
    """What a collection found, and everything it did not read, with reasons."""
    files: list[Path] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)     # could not look: makes a run PARTIAL
    absent: list[Path] = field(default_factory=list)      # named but not there
    skipped_by_suffix: int = 0                            # walk policy, counted, not a gap
    notes: list[str] = field(default_factory=list)        # e.g. a symlink loop, already covered
    scan_dirs: list[Path] = field(default_factory=list)   # directories walked (ack scoping)
    bytecode: list[Path] = field(default_factory=list)    # .pyc/.pyo met by a walk: header-checked

    def __iter__(self):                                   # (files, missing) unpacking, as in 0.1.0
        return iter((self.files, self.absent))


def _drop(en, p, reason: str) -> None:
    en.dropped.append({"file": str(p), "reason": reason})


def _add_file(en: Enumeration, p: Path, seen: set[str]) -> None:
    """Add a regular file once (by real path). Special files are dropped with a
    reason: opening a FIFO would hang, and a device is not text."""
    try:
        st = os.stat(p)
    except OSError as e:
        _drop(en, p, f"cannot stat ({e.__class__.__name__}: broken link or vanished)")
        return
    if not stat.S_ISREG(st.st_mode):
        _drop(en, p, "not a regular file (FIFO, socket or device)")
        return
    real = os.path.realpath(p)
    if real in seen:
        return
    seen.add(real)
    en.files.append(p)


def _walk(en: Enumeration, top: Path, suffixes: tuple[str, ...], seen: set[str],
          visited: set[str]) -> None:
    def onerror(e: OSError) -> None:
        _drop(en, e.filename or top, f"unreadable directory ({e.__class__.__name__})")

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(top, onerror=onerror, followlinks=True):
        real = os.path.realpath(dirpath)
        if real in visited:
            en.notes.append(f"{dirpath}: same real directory already scanned (symlink or repeated "
                            "path), not repeated")
            dirnames[:] = []
            continue
        visited.add(real)
        dirnames.sort()
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1].lower()
            if ext in suffixes or (suffixes is TEXT_SUFFIXES and named_file(name)):
                found.append(Path(dirpath) / name)
            elif ext in detectors.BYTECODE_SUFFIXES:
                en.bytecode.append(Path(dirpath) / name)
            else:
                en.skipped_by_suffix += 1
    for f in found:
        _add_file(en, f, seen)


def collect(paths: list[Path], suffixes: tuple[str, ...] = TEXT_SUFFIXES, *,
            absent_is_dropped: bool = True) -> Enumeration:
    """Expand files and directories. Directories are walked (following symlinked
    directories once each) and filtered by suffix, case-insensitively; a file
    named explicitly is always collected. Paths are de-duplicated by real path.

    `absent_is_dropped`: a path the user NAMED that does not exist is a gap
    (PARTIAL). A preset root that does not exist is not (nothing is there)."""
    en = Enumeration()
    seen: set[str] = set()
    visited: set[str] = set()
    for p in paths:
        if p.is_dir():
            en.scan_dirs.append(p)
            _walk(en, p, suffixes, seen, visited)
        elif os.path.lexists(p):
            _add_file(en, p, seen)
        else:
            en.absent.append(p)
            if absent_is_dropped:
                _drop(en, p, "path does not exist")
    return en


def collect_preset(name: str, root: Path) -> tuple[str, Enumeration]:
    """(provenance, enumeration) for a built-in preset under `root`."""
    provenance, rels = PRESETS[name]
    return provenance, collect([root / r for r in rels], INSTRUCTION_SUFFIXES,
                               absent_is_dropped=False)


@dataclass
class MemoryDiscovery:
    """Memory directories found, plus every project whose memory could not be
    looked at. A directory that is ABSENT is not a gap; one that exists but
    cannot be stat'ed or listed is, and is reported with its cause."""
    dirs: list[Path] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)


_ABSENT = (FileNotFoundError, NotADirectoryError)


def discover_memory_dirs(claude_home: Path | None = None) -> MemoryDiscovery:
    """Every Claude Code auto-memory directory under `claude_home/projects/*/memory`,
    resolved and de-duplicated. Project directories are sometimes symlinks to one
    another; scanning by realpath reads each corpus once.

    Uses explicit stat/listdir calls so a permission error is preserved:
    `Path.is_dir()` returns False for an inaccessible child, which would make an
    unreadable project indistinguishable from one with no memory."""
    root = (claude_home or (Path.home() / ".claude")) / "projects"
    disc = MemoryDiscovery()
    try:
        names = sorted(os.listdir(root))
    except _ABSENT:
        return disc
    except OSError as e:
        _drop(disc, root, f"unreadable directory ({e.__class__.__name__}): projects root")
        return disc
    seen: set[Path] = set()
    for name in names:
        m = root / name / "memory"
        try:
            st = os.stat(m)
        except _ABSENT:
            continue
        except OSError as e:
            _drop(disc, m, f"unreadable directory ({e.__class__.__name__}): project memory "
                           "could not be examined")
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue
        r = m.resolve()
        if r not in seen:
            seen.add(r)
            disc.dirs.append(r)
    return disc


def memory_dirs(claude_home: Path | None = None) -> list[Path]:
    """The discovered directories only (drops are NOT visible here; the CLI uses
    `discover_memory_dirs`)."""
    return discover_memory_dirs(claude_home).dirs

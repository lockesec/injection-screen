"""Pipeline: provenance lanes, kill-chain stages, budgets and session buildup.

Routing is by PROVENANCE, not by phrasing. Indirect injection arrives in content
the agent reads, such as tool output (arXiv 2403.02691). Attacker-controlled
wording can be paraphrased around any pattern, but *which source produced the
content* is not attacker-controlled. So the caller states where content
came from, and the lane decides which detectors apply:

untrusted-web, external-pdf, tool-output,
agent-memory                              ->  FULL lane (every detector)
repo-internal, claude-surface             ->  SMUGGLING lane only

Instruction surfaces and defense docs legitimately QUOTE attack phrases, so the
phrase detectors would flood there, and in this lane they are not run at all.
Hidden payloads (invisible Unicode, HTML comment and hidden-text imperatives,
data: URIs) are never legitimate on those surfaces, so the smuggling lane keeps
exactly those. `html-comment-imperative` and `hidden-text-imperative` are
heuristics and can still flag text that uses the bare words run / ignore /
instructions (docs/detectors.md lists the shapes and the measured rate).

Every finding is assigned a kill-chain stage. The labels (recon ->
weaponization -> delivery -> exploitation) follow the classic Lockheed-style
kill chain; arXiv 2601.09625 motivates the multi-stage framing with its own
seven-stage promptware model, whose stages are different.

Budgets (defense cost matters: arXiv 2602.10453 measures execution-level
defenses at up to 3x baseline cost): per-run limits on file size, file count and wall
clock. The wall clock is checked between detectors, and a file's detector pass is
also cut at the deadline (a POSIX timer on the main thread, see
`detectors._hard_cut`), so one crafted file cannot hold a run past the budget there;
off the main thread only the between-detector checks apply. Each kind is capped per
file. Every file dropped or cut short by a budget is REPORTED, and a run that dropped
anything is PARTIAL. A truncated scan never reads as a clean one.

Session buildup (this project's own design): multi-turn context-buildup attacks
stay under per-file thresholds, so a small state file remembers flagged files per
source family across runs and raises a `session-buildup` finding when the same
family keeps tripping inside the window.
"""
from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path

from . import detectors

STAGE_OF_KIND: dict[str, str] = {
    "recon-prompt-disclosure": "recon",
    "override-instructions": "weaponization",
    "agent-addressed-imperative": "weaponization",
    "jailbreak-persona": "weaponization",
    "model-judge": "weaponization",
    "role-marker": "weaponization",
    "system-tag": "weaponization",
    "role-override": "weaponization",
    "minja-entity-redirect": "weaponization",
    "minja-record-redirect": "weaponization",
    "minja-identifier-redirect": "weaponization",
    "minja-reasoning-steering": "weaponization",
    "minja-error-pretext": "weaponization",
    "minja-priority-note-steering": "weaponization",
    "invisible-unicode": "delivery",
    "html-comment-imperative": "delivery",
    "hidden-text-imperative": "delivery",
    "data-uri": "delivery",
    "js-link": "delivery",
    "unreadable": "delivery",
    "undecodable": "delivery",
    "padding-hidden": "delivery",
    "bytecode-mismatch": "delivery",
    "registry-redirect": "exploitation",
    "session-buildup": "delivery",
    "tool-call-shape": "exploitation",
    "command-lure": "exploitation",
    "exfil-instruction": "weaponization",
    "exfil-image-url": "exploitation",
    "encoded-instruction": "delivery",
    "tool-desc-precondition": "weaponization",
    "tool-desc-secrecy": "weaponization",
    "tool-desc-instruction-tag": "weaponization",
    "tool-desc-cross-reference": "weaponization",
    "agent-audience": "weaponization",
    "silent-compliance": "weaponization",
    "exfil-writeback": "weaponization",
}
STAGES = ("recon", "weaponization", "delivery", "exploitation", "unclassified")

#: provenance -> the kinds its lane keeps (None = every kind).
PROVENANCE_LANES: dict[str, frozenset[str] | None] = {
    "untrusted-web": None,
    "external-pdf": None,
    "tool-output": None,
    "agent-memory": None,          # read back as trusted context next session
    "repo-internal": detectors.SMUGGLING_KINDS,
    "claude-surface": detectors.SMUGGLING_KINDS,
}

DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_MAX_FILES = 2_000
DEFAULT_BUDGET_SECONDS = 120.0
#: The largest wall-clock budget accepted (one day). Larger is not a budget, and an
#: absurd one (`inf`, 1e300) overflows the timer the hard cut is built on.
MAX_BUDGET_SECONDS = 86_400.0

SESSION_WINDOW_S = 24 * 3600
SESSION_BUILDUP_THRESHOLD = 3      # distinct flagged files per family in the window

ACK_FILE = ".injection-scan-ack"


# ------------------------------------------------------------ acknowledgement

def _inside(path: Path, top: Path) -> bool:
    return path == top or top in path.parents


def load_acks(root: Path | None, provenance: str,
              scan_dirs: list[Path] | None = None, *, ack_file: Path | None = None,
              from_root: bool = True) -> tuple[set[str], str | None]:
    """(sha12 fingerprints acknowledged as benign, note). Read from exactly ONE
    file, `<root>/.injection-scan-ack`.

    Scanned content must never be able to acknowledge itself. An ack file is
    plain text and a fingerprint is computable by anyone, so an ack file that
    sits beside or inside the content being screened (a vendored plugin, a
    download) would let that content silence its own findings. Hence:

    * ack files anywhere below the root are never read, only the root's one;
    * with no `root`, nothing is acknowledged;
    * under a full-lane provenance (content you did not write), the root's ack
      file is ignored when it lies inside a directory being scanned, since it
      then is part of that untrusted content. `note` says so.

    Targets outside the root get no acks at all (see `run`).

    File format: one 16-hex fingerprint per line, then a comment saying why it is benign:
        3f2a9c1b7d04e815  # quoted attack example in a security paper, reviewed
    """
    if ack_file is not None:
        f = ack_file                  # the user named it: the one place acks come from
    elif root is not None and from_root:
        f = root / ACK_FILE
    else:
        return set(), None
    if not f.is_file():
        return set(), None
    real = f.resolve()
    if PROVENANCE_LANES.get(provenance) is None:
        for d in scan_dirs or []:
            if _inside(real, d.resolve()):
                return set(), (f"ack file {f} ignored: it lies inside scanned {provenance} "
                               "content, which cannot acknowledge itself")
    try:
        lines = f.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        return set(), f"ack file {f} unreadable ({e.__class__.__name__}); nothing acknowledged"
    acks = set()
    for ln in lines:
        ln = ln.split("#", 1)[0].strip()
        if ln:
            acks.add(ln)
    return acks, None


def ack_files_in_content(root: Path | None, files: list[Path], limit: int = 5) -> list[Path]:
    """Ack files that sit at the root or beside a scanned file. Content you scan can ship
    one, so none is read unless the user names it (`--ack-file`); these are reported."""
    seen: dict[Path, None] = {}
    dirs = ([root] if root is not None else []) + [f.parent for f in files]
    for d in dirs:
        c = d / ACK_FILE
        try:
            if c.is_file():
                seen.setdefault(c.resolve(), None)
        except OSError:
            continue
        if len(seen) >= limit:
            break
    return list(seen)


def fingerprint_name(path: Path, root: Path | None) -> tuple[str, bool]:
    """(name used in the fingerprint, inside_root). Inside the root it is the
    root-relative path in POSIX form, so an ack names ONE file and survives a
    move of the whole project."""
    if root is None:
        return str(path.name), False
    real, top = path.resolve(), root.resolve()
    if top in real.parents:
        return real.relative_to(top).as_posix(), True
    return str(path.name), False


# ------------------------------------------------------------ session state

def default_state_path() -> Path:
    """`$INJECTION_SCREEN_STATE`, else `$XDG_STATE_HOME/injection-screen/session.json`
    (default `~/.local/state/...`)."""
    env = os.environ.get("INJECTION_SCREEN_STATE")
    if env:
        return Path(env)
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "injection-screen" / "session.json"


def _load_state(path: Path) -> tuple[dict, str | None]:
    """(state, problem). An ABSENT file is a first run, not a problem. A file
    that exists and cannot be read or parsed IS one: buildup detection then
    starts from nothing, so a clean verdict from this run would claim more than
    was checked (the run is marked degraded; see `run`)."""
    empty = {"families": {}}
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return empty, None
    except (OSError, UnicodeDecodeError) as e:
        return empty, f"session state unreadable ({e.__class__.__name__}): {path}"
    try:
        state = json.loads(raw)
    except RecursionError:
        return empty, f"session state is nested too deeply to read (RecursionError): {path}"
    except (ValueError, OverflowError, MemoryError) as e:
        return empty, f"session state is not valid JSON ({e.__class__.__name__}): {path}"
    fams = state.get("families") if isinstance(state, dict) else None
    try:
        shaped = isinstance(fams, dict) and all(
            isinstance(r, dict) and isinstance(r.get("files", {}), dict)
            and all(isinstance(ts, (int, float)) and not isinstance(ts, bool)
                    and math.isfinite(ts) for ts in r.get("files", {}).values())
            for r in fams.values())
    except (OverflowError, ValueError):       # an integer too large to be a time
        shaped = False
    if not shaped:
        return empty, f"session state has an unexpected shape: {path}"
    return state, None


def _prune_state(state: dict, now: float) -> None:
    for fam, rec in list(state["families"].items()):
        rec["files"] = {f: ts for f, ts in rec.get("files", {}).items()
                        if now - ts < SESSION_WINDOW_S}
        if not rec["files"]:
            del state["families"][fam]


def _family(provenance: str, path: Path) -> str:
    """Buildup aggregates per provenance per directory. Keyed by the RESOLVED
    directory, not its bare name, so two unrelated `docs/` folders never merge."""
    return f"{provenance}:{path.resolve().parent}"


# ------------------------------------------------------------ the run

def run(files: list[Path], provenance: str, *,
        root: Path | None = None,
        ack_file: Path | None = None,
        ack_from_root: bool = True,
        scan_dirs: list[Path] | None = None,
        dropped: list[dict] | None = None,
        state_path: Path | None = None,
        session: bool = True,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
        budget_seconds: float = DEFAULT_BUDGET_SECONDS,
        now: float | None = None,
        bytecode: list[Path] | None = None) -> dict:
    """Scan `files` under `provenance` routing and return the result.

    `root` is the project root: the only place an ack file is read from, and
    the base of each fingerprint's path. `scan_dirs` are the directories the
    files were collected from (for ack scoping). `dropped` carries what
    enumeration could not read (see `surfaces.collect`), so `complete` is
    decided here, once, for the library and the CLI alike.

    The result always itemizes `dropped` files and says whether the run was
    `complete`: False if anything was dropped, a kind was capped
    (`truncated`), or the session memory was degraded.
    """
    if provenance not in PROVENANCE_LANES:
        raise ValueError(f"unknown provenance {provenance!r}; one of {sorted(PROVENANCE_LANES)}")
    if not (max_file_bytes > 0 and max_files > 0 and budget_seconds > 0):
        raise ValueError("budgets must be greater than 0")
    if not budget_seconds <= MAX_BUDGET_SECONDS:         # also false for nan and inf
        raise ValueError(f"budget_seconds must be finite and at most {MAX_BUDGET_SECONDS:g}")
    lane = PROVENANCE_LANES[provenance]
    now = time.time() if now is None else now
    deadline = time.monotonic() + budget_seconds
    dropped = list(dropped or [])
    truncated: list[dict] = []
    notes: list[str] = []

    if len(files) > max_files:
        dropped += [{"file": detectors.display_path(p), "reason": "max-files budget"}
                    for p in files[max_files:]]
        files = files[:max_files]

    acks, ack_note = load_acks(root, provenance, scan_dirs, ack_file=ack_file,
                               from_root=ack_from_root)
    if ack_note:
        notes.append(ack_note)
    if ack_file is None and not ack_from_root:
        for c in ack_files_in_content(root, files):
            notes.append(f"{detectors.display_path(c)} is an acknowledgement file in or beside "
                         "the content being scanned; not honoured. Acknowledgements are read only "
                         "from a file you name with --ack-file")

    findings: list[dict] = []
    flagged: set[str] = set()
    scanned = 0
    acknowledged = 0
    bytecode_checked = 0
    for f in files:
        shown = detectors.display_path(f)
        if time.monotonic() > deadline:
            dropped.append({"file": shown, "reason": "wall-clock budget"})
            continue
        try:
            size = f.stat().st_size
        except OSError as e:
            dropped.append({"file": shown, "reason": f"stat failed: {e}"})
            continue
        if size > max_file_bytes:
            dropped.append({"file": shown, "reason": f"max-file-bytes budget ({size}b)"})
            continue
        fp_name, inside = fingerprint_name(f, root)
        found, rep, over = detectors.read_and_scan(f, fp_name=fp_name, deadline=deadline,
                                                   max_bytes=max_file_bytes, kinds=lane)
        if over:
            dropped.append({"file": shown, "reason": over})
            continue
        if rep.note:
            notes.append(f"{shown}: {rep.note}")
        if rep.undecoded:
            notes.append(f"{shown}: {rep.undecoded} character(s) did not decode; read as if absent")
        kept = 0
        for x in found:
            if lane is not None and x["kind"] not in lane:
                continue
            if inside and x["sha12"] in acks:
                acknowledged += 1
                continue
            x["stage"] = STAGE_OF_KIND.get(x["kind"], "unclassified")
            findings.append(x)
            kept += 1
        if kept:
            flagged.add(str(f.resolve()))
        for kind in rep.capped:
            if lane is None or kind in lane:
                truncated.append({"file": shown, "kind": kind,
                                  "cap": detectors.MAX_FINDINGS_PER_KIND})
        if rep.deadline_hit:
            dropped.append({"file": shown, "reason": "wall-clock budget (stopped mid-file; "
                                                     "findings from it are a floor)"})
            continue
        scanned += 1

    # Bytecode is never read as text; its header is checked against its source.
    for f in bytecode or []:
        if time.monotonic() > deadline:
            dropped.append({"file": detectors.display_path(f), "reason": "wall-clock budget"})
            continue
        reason = detectors.check_bytecode(f)
        bytecode_checked += 1
        if reason is None:
            continue
        fp_name, inside = fingerprint_name(f, root)
        x = detectors.finding(f, 0, "MEDIUM", "bytecode-mismatch", reason, fp_name=fp_name)
        if lane is not None and x["kind"] not in lane:
            continue
        if inside and x["sha12"] in acks:
            acknowledged += 1
            continue
        x["stage"] = STAGE_OF_KIND["bytecode-mismatch"]
        findings.append(x)
        flagged.add(str(f.resolve()))

    session_status = {"status": "off"}
    if session:
        extra, problem = _session_buildup(flagged, provenance,
                                          state_path or default_state_path(), now,
                                          touched={_family(provenance, f) for f in files})
        findings += extra
        session_status = ({"status": "degraded", "reason": problem} if problem
                          else {"status": "ok"})

    return {
        "provenance": provenance,
        "lane": "full" if lane is None else "smuggling",
        "scanned": scanned,
        "bytecode_checked": bytecode_checked,
        "acknowledged": acknowledged,
        "findings": findings,
        "dropped": dropped,
        "truncated": truncated,
        "notes": notes,
        "complete": not dropped and not truncated and session_status["status"] != "degraded",
        "session": session_status,
        "stages": {s: sum(1 for x in findings if x["stage"] == s) for s in STAGES},
    }


def _session_buildup(flagged: set[str], provenance: str, state_path: Path,
                     now: float, *, touched: set[str]) -> tuple[list[dict], str | None]:
    """`flagged` holds RESOLVED paths, so one file reached by two spellings
    (relative, absolute, via ..) is one file, not two. `touched` is the set of
    families (same provenance, resolved directory) this run scanned a file in:
    only those can report, so scanning an unrelated project never raises another
    directory's alert. All stored families are still updated and saved."""
    state, problem = _load_state(state_path)
    _prune_state(state, now)
    for fp in sorted(flagged):
        fam = _family(provenance, Path(fp))
        state["families"].setdefault(fam, {"files": {}})["files"][fp] = now
    out: list[dict] = []
    for fam, rec in state["families"].items():
        if fam in touched and len(rec["files"]) >= SESSION_BUILDUP_THRESHOLD:
            earlier = sum(1 for f in rec["files"] if f not in flagged)
            directory = fam[len(provenance) + 1:]
            x = detectors.finding(
                Path(directory), 0, "HIGH", "session-buildup",
                f"{len(rec['files'])} flagged files in this directory within "
                f"{SESSION_WINDOW_S // 3600}h under provenance {provenance}, {earlier} "
                f"remembered from earlier runs (reset: --no-session or delete the state file)")
            x["stage"] = STAGE_OF_KIND["session-buildup"]
            out.append(x)
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_path.with_name(state_path.name + ".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, state_path)
    except OSError as e:
        # This run's buildup check ran, but the next run starts blind, so the
        # memory the check depends on is broken. Say so rather than pass.
        problem = problem or f"session state not writable ({e.__class__.__name__}): {state_path}"
    return out, problem

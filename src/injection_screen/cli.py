"""Command line: `injection-screen`.

    injection-screen PATH... --provenance untrusted-web
    injection-screen --preset claude-code --root .
    injection-screen --memory

Exit codes:

    0   clean, and the scan was complete
    1   findings (review each one; see "Acknowledging a finding" in docs/usage.md)
    2   NOT EVALUABLE: nothing could be scanned (no memory dirs, every path
        missing). This is never a pass.
    3   PARTIAL: no findings, but part of the input was not screened: a
        budget dropped or cut short a file, a named path was missing, a
        directory could not be read, a special file was met, or the
        session-buildup memory was damaged or unwritable. Not a clean verdict;
        fix the cause and re-run (or pass --no-session on purpose).
    64  usage error (including a --budget-seconds that is not finite or exceeds a day)
    70  INTERNAL ERROR: the screen itself crashed. Nothing is claimed about
        the input; never read this as findings or as clean.

Findings found under a tripped budget still exit 1: they are a floor, not a
census, and a PARTIAL line says so.

A reader that closes the pipe early (`injection-screen ... | head -1`) does not
change the verdict: output is dropped from then on and the exit code is the one
above, not Python's 120 for a failed flush.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

from . import judge, __version__, detectors, pipeline, surfaces

EXIT_CLEAN, EXIT_FINDINGS, EXIT_NOT_EVALUABLE, EXIT_PARTIAL, EXIT_USAGE = 0, 1, 2, 3, 64
EXIT_INTERNAL = 70


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="injection-screen", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Screen text for prompt injection before an AI agent reads it. Offline, "
                    "deterministic, no dependencies. Say where the content came from "
                    "(--provenance) and that picks the checks. Each finding is one line "
                    "with a file, a line number and a fingerprint.",
        epilog="Exit codes: 0 clean, 1 findings, 2 not evaluable (nothing could be scanned),\n"
               "3 partial (part of the input was not screened), 64 usage error, 70 crash.\n\n"
               "Other commands:\n"
               "  injection-screen hook run|install|check [--root DIR] [--run-registered]\n"
               "      the Claude Code PostToolUse hook: run it, print its settings snippet,\n"
               "      or test that its warning reaches the model\n"
               "  injection-screen tools pin|check TOOLS.json --pin PINFILE\n"
               "      record MCP tool definitions, then name any that changed")
    ap.add_argument("paths", nargs="*", type=Path, help="files to screen (read whatever the suffix) or directories (a walk reads prose, markup, "
                         "notebook, data and script files, listed in docs/usage.md, and checks .pyc headers)")
    src = ap.add_argument_group("what to scan (choose one)")
    src.add_argument("--provenance", choices=sorted(pipeline.PROVENANCE_LANES),
                     help="where PATHS came from; required with PATHS. untrusted-web, external-pdf, tool-output and "
                          "agent-memory run every check; repo-internal and claude-surface run only the "
                          "hidden-text checks")
    src.add_argument("--preset", choices=sorted(surfaces.PRESETS),
                     help="screen a built-in set of files under --root (claude-code: CLAUDE.md, AGENTS.md and the "
                          ".claude skills, agents, commands, rules)")
    src.add_argument("--memory", action="store_true",
                     help="screen Claude Code auto-memory (~/.claude/projects/*/memory) with every check")
    ap.add_argument("--root", type=Path, default=Path("."),
                    help="project root for --preset and the base of each fingerprint's path "
                         "(default: .). It does not name an ack file")
    ap.add_argument("--ack-file", type=Path, default=None,
                    help="the one file of acknowledged fingerprints to honour. Acks are never "
                         "found in or beside the scanned content. With --memory they come from "
                         "the Claude home (~/.claude/.injection-scan-ack) and this flag is not allowed")
    ap.add_argument("--claude-home", type=Path, default=None, help="Claude home for --memory (default: ~/.claude)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON on stdout")
    ap.add_argument("--no-session", action="store_true", help="do not read or write the cross-run buildup state")
    ap.add_argument("--session-state", type=Path, default=None,
                    help="session-buildup state file (default: $INJECTION_SCREEN_STATE, else $XDG_STATE_HOME/injection-screen/session.json)")
    ap.add_argument("--budget-files", type=int, default=pipeline.DEFAULT_MAX_FILES,
                    help="most files to read in one run; the rest are reported and the run exits 3 "
                         "(default: %(default)s)")
    ap.add_argument("--budget-bytes", type=int, default=pipeline.DEFAULT_MAX_FILE_BYTES,
                    help="largest file to read, in bytes; a bigger one is reported, not read "
                         "(default: %(default)s)")
    ap.add_argument("--budget-seconds", type=float, default=pipeline.DEFAULT_BUDGET_SECONDS,
                    help="wall-clock limit for the run; a file cut short is reported and the run "
                         "exits 3 (default: %(default)s)")
    jd = ap.add_argument_group("optional model judge (off by default; sends text to the model)")
    jd.add_argument("--judge", metavar="MODEL", default=None,
                    help="also ask this Ollama model about each file. It can add a finding and can "
                         "never remove one. Not deterministic. Off by default")
    jd.add_argument("--judge-url", default=judge.DEFAULT_URL,
                    help="where the text is sent (default: %(default)s, this machine)")
    jd.add_argument("--judge-timeout", type=float, default=judge.DEFAULT_TIMEOUT,
                    help="seconds for one model call (default: %(default)s)")
    jd.add_argument("--judge-max-calls", type=int, default=judge.DEFAULT_MAX_CALLS,
                    help="most model calls in one run; what is left is reported and the run exits 3 "
                         "(default: %(default)s)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _usage(msg: str) -> int:
    print(f"injection-screen: error: {msg}", file=sys.stderr)
    return EXIT_USAGE


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Any unexpected exception exits 70, never 1 (findings) or 0.
    `injection-screen hook run | install | check` drives the Claude Code hook, and
    `injection-screen tools pin | check` pins MCP tool definitions (a path literally named
    `hook` or `tools` is given as `./hook`, `./tools`)."""
    if argv is None:
        argv = sys.argv[1:]
    try:
        if argv and argv[0] == "hook":
            from . import hook
            return hook.dispatch(list(argv[1:]))
        if argv and argv[0] == "tools":
            from . import tools
            return tools.dispatch(list(argv[1:]))
        return _main(argv)
    except BrokenPipeError:
        # Raised by _main only before it knew the verdict; nothing to report.
        _drop_stdout()
        return EXIT_INTERNAL
    except Exception as e:  # noqa: BLE001 - the crash contract is the point
        print(f"INTERNAL ERROR: {e.__class__.__name__}: {e}. Nothing was evaluated; "
              "this is not a pass and not a finding count.", file=sys.stderr)
        return EXIT_INTERNAL


def _drop_stdout() -> None:
    """The reader of our stdout went away. Point the descriptor at /dev/null so the
    interpreter's own flush at exit cannot fail with status 120."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def _emit(res: dict, en, degraded: bool, as_json: bool) -> None:
    """Print the result. A closed pipe is not a failure of the scan: stop printing."""
    try:
        _print_result(res, en, degraded, as_json)
        sys.stdout.flush()
    except BrokenPipeError:
        _drop_stdout()


def _print_result(res: dict, en, degraded: bool, as_json: bool) -> None:
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        for x in res["findings"]:
            print(f"{x['tier']:6} {x['stage']:14} {x['kind']:28} "
                  f"{x['file']}{':%d' % x['line'] if x['line'] else ''}  "
                  f"[{x['sha12']}]  {x['excerpt']}")
        for d in res["dropped"]:
            print(f"DROPPED {d['file']}: {d['reason']}", file=sys.stderr)
        for t in res["truncated"]:
            print(f"TRUNCATED {t['file']}: more than {t['cap']} {t['kind']} matches; "
                  "only the first are listed", file=sys.stderr)
        for n in res["notes"]:
            print(f"NOTE {n}", file=sys.stderr)
        if degraded:
            print(f"SESSION DEGRADED: {res['session']['reason']}. Cross-run buildup "
                  "detection is not working.", file=sys.stderr)
        print(f"SUMMARY: provenance={res['provenance']} lane={res['lane']} "
              f"scanned={res['scanned']} bytecode_checked={res['bytecode_checked']} "
              f"findings={len(res['findings'])} acknowledged={res['acknowledged']} "
              f"dropped={len(res['dropped'])} skipped_by_suffix={en.skipped_by_suffix} "
              f"stages={res['stages']}")
        if res.get("judge"):
            j = res["judge"]
            print(f"JUDGE: model={j['model']} status={j['status']} calls={j['calls']} "
                  f"added={j['added']} not_judged={len(j['not_judged'])}")


def _main(argv: list[str] | None) -> int:
    ap = _parser()
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:                    # argparse exits 2; 2 is reserved for NOT EVALUABLE
        return EXIT_CLEAN if e.code == 0 else EXIT_USAGE
    if a.judge and not judge.usable_url(a.judge_url):
        return _usage("--judge-url must be an http or https address")

    if not math.isfinite(a.budget_seconds):
        return _usage(f"--budget-seconds is not finite (got {a.budget_seconds}); give a number "
                      f"of seconds, at most {pipeline.MAX_BUDGET_SECONDS:g}")
    for flag, val in (("--budget-files", a.budget_files), ("--budget-bytes", a.budget_bytes),
                      ("--budget-seconds", a.budget_seconds)):
        if not val > 0:
            return _usage(f"{flag} must be greater than 0 (got {val})")
    if not a.budget_seconds <= pipeline.MAX_BUDGET_SECONDS:
        return _usage(f"--budget-seconds must be at most "
                      f"{pipeline.MAX_BUDGET_SECONDS:g} (got {a.budget_seconds})")

    modes = sum([bool(a.paths), bool(a.preset), a.memory])
    if modes != 1:
        return _usage("give exactly one of: PATHS (with --provenance), --preset, --memory")

    if a.provenance is not None and (a.preset or a.memory):
        return _usage("--provenance is for PATHS; --preset and --memory fix their own lane, so the "
                      "flag would be ignored. Drop it, or name the paths instead")
    if a.ack_file is not None and a.memory:
        return _usage("--ack-file cannot be combined with --memory (memory acks come from the Claude home)")
    if a.preset:
        provenance, en = surfaces.collect_preset(a.preset, a.root)
    elif a.memory:
        provenance = "agent-memory"
        disc = surfaces.discover_memory_dirs(a.claude_home)
        dirs = disc.dirs
        if not dirs:
            where = (a.claude_home or Path("~/.claude")) / "projects" / "*" / "memory"
            for d in disc.dropped:
                print(f"DROPPED {detectors.display_path(d['file'])}: {d['reason']}", file=sys.stderr)
            print(f"NOT EVALUABLE: no readable memory directory found under {where} "
                  f"({len(disc.dropped)} unreadable). "
                  "Nothing was scanned. This is not a pass.", file=sys.stderr)
            return EXIT_NOT_EVALUABLE
        en = surfaces.collect(dirs)
        en.dropped = disc.dropped + en.dropped
        memory_dirs = dirs
        # Memory lives outside any project, so its acknowledgements are read from the Claude
        # home (`~/.claude/.injection-scan-ack`), which lies outside every memory directory:
        # memory content still cannot acknowledge itself. Fingerprints then name a memory
        # file by its path under the Claude home.
        ack_root = (a.claude_home or Path.home() / ".claude").expanduser()
    else:
        if a.provenance is None:
            # Routing is by provenance. Guessing it from the text would be the
            # attacker-steerable heuristic this tool exists to avoid.
            return _usage("--provenance is required with PATHS")
        provenance = a.provenance
        en = surfaces.collect(a.paths)

    if not en.files and not en.bytecode:
        for d in en.dropped:
            print(f"DROPPED {detectors.display_path(d['file'])}: {d['reason']}", file=sys.stderr)
        if a.memory:
            print(f"NOT EVALUABLE: {len(memory_dirs)} memory director"
                  f"{'y' if len(memory_dirs) == 1 else 'ies'} found "
                  f"({', '.join(detectors.display_path(d) for d in memory_dirs)}) but no scannable "
                  f"files in them ({en.skipped_by_suffix} skipped by suffix). Nothing was "
                  "scanned. This is not a pass.", file=sys.stderr)
        else:
            what = ", ".join(detectors.display_path(m) for m in en.absent) or "the given paths"
            print(f"NOT EVALUABLE: 0 files collected ({what}; {en.skipped_by_suffix} skipped by "
                  "suffix). Nothing was scanned. This is not a pass.", file=sys.stderr)
        return EXIT_NOT_EVALUABLE

    dropped = [{"file": detectors.display_path(d["file"]), "reason": d["reason"]}
               for d in en.dropped]
    res = pipeline.run(en.files, provenance, root=ack_root if a.memory else a.root,
                       ack_file=a.ack_file, ack_from_root=bool(a.memory),
                       scan_dirs=en.scan_dirs,
                       dropped=dropped,
                       state_path=a.session_state, session=not a.no_session,
                       max_file_bytes=a.budget_bytes, max_files=a.budget_files,
                       budget_seconds=a.budget_seconds, bytecode=en.bytecode)
    res["enumeration"] = {
        "collected": len(en.files),
        "skipped_by_suffix": en.skipped_by_suffix,
        "absent": [detectors.display_path(m) for m in en.absent],
    }
    res["notes"] = res["notes"] + [detectors.display_path(n) for n in en.notes]
    if a.preset and en.absent:
        res["notes"].append(f"{len(en.absent)} preset location(s) absent (nothing there to "
                            f"scan): " + ", ".join(res["enumeration"]["absent"]))
    if a.judge:
        judge.apply(res, en.files, a.judge, url=a.judge_url, timeout=a.judge_timeout,
                    max_calls=a.judge_max_calls, root=ack_root if a.memory else a.root,
                    ack_file=a.ack_file, ack_from_root=bool(a.memory), scan_dirs=en.scan_dirs, max_file_bytes=a.budget_bytes)
    degraded = res["session"]["status"] == "degraded"

    _emit(res, en, degraded, a.json)

    if res["findings"]:
        if not res["complete"]:
            print("PARTIAL: part of the check did not run (dropped or truncated files, or a "
                  "degraded session); the findings above are a floor, not a census.",
                  file=sys.stderr)
        return EXIT_FINDINGS
    if not res["complete"]:
        print("PARTIAL, no findings: this is NOT a clean verdict. Fix the dropped paths, "
              "raise the budgets, or repair the session state, and re-run.", file=sys.stderr)
        return EXIT_PARTIAL
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())

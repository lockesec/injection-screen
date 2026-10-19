# Changelog

## 0.1.0 (2026-10-19)

First public release. What it does is below; the hardening history is in
[DESIGN.md](DESIGN.md).

**Screening**

- Routes by provenance. Content from outside your control gets every detector (the full
  lane). Your own instruction files get only the hidden-text detectors (the smuggling lane).
- Sources: paths, `--preset claude-code` for a project's instruction files, and `--memory`
  for Claude Code's auto-memory.
- Exit codes: 0 clean, 1 findings, 2 not evaluable, 3 partial, 64 usage, 70 internal error.
  Nothing exits 0 on input it did not screen, except the files a directory walk skips by
  suffix, which are counted (`skipped_by_suffix` in the SUMMARY line).
- A directory walk reads Markdown dialects, reStructuredText, AsciiDoc, HTML, XML, SVG,
  notebooks, JSON, YAML, TOML, INI and scripts (exact list in docs/usage.md), checks the
  header of `.pyc` and `.pyo` files, and reads well-known config and build files by name
  (`.npmrc`, `.pypirc`, `Dockerfile`, `Makefile`, `.env`, ...). A file named on the
  command line is read whatever its suffix.
- Acknowledgements by fingerprint (64 bits over the whole flagged text), read only from
  `<root>/.injection-scan-ack`, so scanned content cannot acknowledge itself. `--memory`
  reads them from `~/.claude/.injection-scan-ack`.
- Session buildup across runs (per directory, 24 hours), and budgets on file size, file
  count and wall-clock time. `--budget-seconds` is a hard bound on a POSIX main thread.

**Detectors**

- Full lane: override and role-takeover phrasing (English, plus German variants), tool-call
  shapes, pipe-to-shell and recursive-delete lures, prompt-disclosure requests, six
  memory-poisoning shapes, text that addresses the agent reading it (`agent-audience`,
  `silent-compliance`, `exfil-writeback`), exfiltration through image URLs
  (`exfil-image-url`, `exfil-instruction`), and base64, hex or percent-encoded runs that
  decode to an instruction (`encoded-instruction`).
- MCP tool poisoning: `tool-desc-precondition`, `tool-desc-secrecy`,
  `tool-desc-instruction-tag`, `tool-desc-cross-reference`. `tools pin` and `tools check`
  name any tool whose definition changed after it was pinned.
- `registry-redirect`: a parser, not one regex, that judges each package-registry URL on its
  parsed hostname (pip, npm, uv, and the config files and flags that set them). The covered
  forms and what is not covered are in docs/detectors.md.
- Smuggling lane: `invisible-unicode`, `padding-hidden`, `bytecode-mismatch`,
  `html-comment-imperative` and `hidden-text-imperative` (comments and hidden elements that
  give orders, read from the raw file), `javascript:` and `data:` links, and `undecodable`
  or `unreadable` files.

**Claude Code hook**

- `injection-screen hook run` is the PostToolUse hook, with a hard 5 s deadline that fails
  open. `hook install` prints the settings snippet. `hook check` runs each registered
  command on a planted injection and passes only when the warning reaches the model's
  context, which is how to find the hook's silent fail-open cases.

**Measured**

- deepset/prompt-injections held-out test split: 12 of 60 injections, 0 of 56 benign.
- A held-out set written blind by a separate agent for the agent-addressed detectors: 6 of 25
  attacks, 0 of 40 benign (docs/detectors.md).
- InjecAgent: 1,054 of 1,054 injections with override wording, 0 of 1,054 plain requests,
  0 of 17 benign templates.
- Trail of Bits overtly-malicious-skills: 4 of 4 in the full lane, 3 of 4 in the skill lane.
  The detectors were written after studying it, so it is a regression check.
- `benchmarks/run_all.py` reruns every public benchmark and `--write` regenerates
  docs/benchmark-results.md.

**Docs and CI**

- The README quick-start transcript is checked against the tool's real output in CI
  (`examples/check_readme.py`). The project's own docs are screened in CI under
  `repo-internal` with a committed ack file.

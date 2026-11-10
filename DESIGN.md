# How injection-screen was built

## Starting point

The screen began as a check inside a private AI-experimentation environment, which
fetched web pages, read tool output and re-read its own memory files. This tool is a
clean rewrite against a short contract, not a copy of that check. The contract:

1. **Route by provenance, not only by content.** Attacker wording can be
   paraphrased around any pattern. Where the content came from cannot be, so the
   caller states it and the lane decides which detectors run.
2. **Never exit 0 on content it did not screen.** Unreadable, missing, oversized
   and undecodable input is reported, and the run is PARTIAL (3) or NOT
   EVALUABLE (2).
3. **Scanned content can never suppress its own findings.**
4. **Standard library only.** That leaves no dependency supply chain to audit.

## Hardening history

Separate AI sessions that had not written the code reviewed the tool in thirteen adversarial rounds.
Each finding was reproduced against the source and pinned to a test before it was fixed,
and each round's findings were fixed before the next, one of them by the maintainer after two failed attempts. The table says what each round found.

| Round | Date | What it found |
|---|---|---|
| 1 | 2026-09-24 | An unreadable file in the smuggling lane exited 0. The acknowledgement walk climbed above `--root`, so a planted ack file could silence findings. A damaged session-state file read as a working check. |
| 2 | 2026-09-25 | A readable file next to an unreadable subdirectory exited 0 and reported `complete: true`; the subdirectory vanished from the scan. The library and the CLI disagreed on completeness. |
| 3 | 2026-09-25 | Further paths that exited clean on unscreened or self-acknowledged content. These were closed in d73de2d. |
| 4 | 2026-09-26 | `--memory` silently skipped an unreadable project directory when another one was readable. The paper citations were also re-checked against what each paper actually shows. |
| 5 | 2026-10-15 | Pre-release review. It found no fail-open path and no ReDoS: 24 adversarial 1 MB inputs ran in 0.93 s or less (the author's own timing; the inputs are not shipped). Homoglyph and encoding evasions were undocumented, and they are now listed under Known limits. 158 tests pass. |
| 6 | 2026-10-15 | Recall work on the Trail of Bits corpus. It found a quadratic regex: `role-marker` was `^\s*` under `re.M`, so a file of 100,000 blank lines took over a minute, and at that point the time budget could not interrupt a single regex (it can now, on the main thread of a POSIX process; see [docs/detectors.md](docs/detectors.md)). Three structural detectors went from 1 of 4 to 4 of 4 (full lane), with 0 false positives on about 2,000 benign files (private corpora, not reproducible; see [docs/measured-recall.md](docs/measured-recall.md)). 190 tests pass. |
| 7 | 2026-10-15 | Review of the `registry-redirect` parser. Its scan was quadratic: a registry key followed by 120 KB of whitespace took 124 s, and `uv x ` repeated to 2 MB took 193 s, while a run with `--budget-seconds 1` exited 0 after 3.6 s on 20,000 spaces, because the budget was only checked between detectors and a clean-looking scan that overran it was still reported complete. The parser is now linear (over 200 adversarial shapes at about 1 MB each, timed in the test suite), the budget cuts a detector mid-run and the run is partial, and a set of documented forms it missed (uv list values and index tables, multi-line `pip.conf` values, control-character userinfo, options inside `sh -c`, JSON keys, Makefile assignments, requirements option lines, uv global options) are covered or listed as not covered. 737 tests pass. |
| 8 | 2026-10-15 | Found: the earlier registry fix was incomplete. The registry prefilter `_QUICK` was still quadratic on a word made of one tool name repeated (`pip` x 13,333: 0.34 s at 10 KB, 5.4 s at 40 KB; 400 KB of `uv` ran for minutes), so the claim "linear in the input" was false for the shape a hostile page would use. A match can now only start at a word start (40 KB: under 2 ms). Every other regex in the package was then timed on repetitions of its own words, and a test does it; none had the flaw, and the claim is now worded as measured: the registry scan is linear (timed), the phrase patterns have bounded windows, and the wall-clock budget is the backstop. The example hook had no deadline and could be handed JSON that produced a traceback; it now has a hard 5 s bound and fails open on every error. `html-comment-imperative` fired on `prettier-ignore`, on a `<!--` in code spans and fences, and on Python sources; it is narrowed and its remaining false-positive shapes are written down. A damaged session-state file and an absurd `--budget-seconds` crashed with exit 70; they are now exit 3 and 64. The pattern: the earlier fix covered the instance the reviewer showed and claimed the class closed. 809 tests pass. |
| 9 | 2026-10-15 | Found: the previous fix had made `html-comment-imperative` quiet on `prettier-ignore`, code spans, fences and maintainer notes by blanking text before the search; each blanking was a bypass: a payload in backticks, a hyphen-joined payload, `please run` of a secret read, and any comment after a stray backtick, an indented fence or a `<div>` line was invisible, in the lane meant for the owner's own files. The model reads the raw file, so renderer state decides nothing. The check now examines every comment, normalises separators before the search, searches the HIGH phrase patterns too, and excuses only a whole-comment tool directive from a short list; the false-positive cost is stated in the README. The README transcript had drifted from the real output and CI's `check_readme` would have failed; a test now runs it. The pattern: a false-positive fix that blanks input trades one error for a silent one, and in a security tool the silent one is the worse. 869 tests pass. |
| 10 | 2026-10-15 | Found: the comment check found its spans in NFKC-folded text, but a renderer does not fold: a comment closed by `--` plus a fullwidth `>` (or fullwidth or small-form hyphens) ended early for the scanner while the renderer kept hiding the rest, exit 0 in the lane meant for the owner's own files. Spans are now found in the raw text and only the body is folded. The docs claimed the other detectors cover any non-comment hidden text; none did (`display:none`, `hidden`, `<template>`, `<noscript>`, `font-size:0`, `[//]: #` comments, link titles, browser bogus comments and CDATA all gave 0 findings). They are now read as `hidden-text-imperative` / extended `html-comment-imperative`, and the false-negative list names what remains unread. Directory walks passed over `.mdx`, `.html`, `.rst`, `.adoc`, `.ipynb`, `.json`, `.yaml`... at exit 0; the suffix list is now wide and documented. The example hook's `json.loads` overflows at about 100,000 levels, which skipped the screen silently; the model is now told. More tool directives are excused (doctoc, cspell, all-contributors, ...) with argument shapes that cannot carry a sentence, the false-positive rate is stated with its corpus, and the project's own docs are screened in CI. The pattern: the previous fix closed the instance (separator folding) and left the model of the renderer (what a renderer does NOT fold) unexamined. 1,057 tests pass. |
| 11 | 2026-10-15 | Found: six bypasses of the comment and hidden-text checks in the smuggling lane: an unclosed `<script>` mention blinded the rest of a file; tool-directive and `<noscript>` exemptions could carry an instruction; an acknowledgement keyed on a 120-character excerpt excused a payload appended to the same comment; JSON-escaped markup in notebooks was not read; and `/>` closed a hidden HTML element. Fixed on one rule (an exemption excuses the word search, never the HIGH phrases), raw text only for closed elements in HTML files, fingerprints over the whole flagged text (64 bits), JSON escapes undone in place, browser-like attribute parsing, CSS decoding, SVG presentation attributes, parser-like close-tag matching, and over-cap bodies reported instead of skipped. Fixed by the maintainer directly after two failed fix rounds. |
| 12 | 2026-10-15 | Found: JSON escapes were padded in place, so surrogate pairs and an escape inside a token (`\u003c!--`) still evaded the notebook and JSON checks; a `<script>` mention inside a comment, attribute or textarea opened a raw-text range; tags were stripped from hidden bodies before the HIGH search (`<system>`); the Doxygen exemption could carry a comma-joined instruction; acknowledgements keyed on a phrase's prefix or on the first 64 KB of a hidden body. Fixed: JSON strings decoded as a parser decodes them with positions mapped back, text outside strings read too; raw-text openers found by a parser-like pass; HIGH phrases searched in the raw hidden body; the Doxygen exemption removed (Doxygen HTML now trips the check, documented); fingerprints over the whole line for phrases, the element and its raw body for hidden text, and everything to the end of the file past the cap; link labels with escapes and a line break. Fixed by the maintainer directly. |
| 13 | 2026-10-16 | Found: the new JSON string regex capped a string at 1,000,000 characters (a valid notebook with a large image output then lost quote pairing and was under-read) and was quadratic on escaped quotes; a damaged string, an invalid escape or a JSONC comment disabled decoding; a cell's `source` lines were joined with line breaks; the phrase patterns did not read decoded JSON; several browser contexts (bogus comments, raw-text elements, unquoted attributes) still let a `<script>` mention open a range or a `</div>` end a hidden element; the restated false-positive numbers counted other kinds. Fixed by the maintainer: a linear JSON scanner with no cap, per-escape decoding, comment skipping and array joining; phrases read decoded strings; the browser contexts modelled in both scans, with an unclosed quoted attribute running to the end of the file; the numbers re-measured counting only these kinds (they match the earlier figures). |

The pattern across rounds 1-5 was the same: every real defect was a path that
**reported clean when it had not looked**. None was a missed detection. Round 6
was the first to work on recall, and it found that the payloads a phrase screen
misses still leave a structural mark: where they are hidden, or what they have to
write to take effect. That is
why the exit-code contract carries the weight of the design.

## Deliberate non-goals

- **No model calls.** A semantic judge is the stronger check. This screen decides
  what that judge, or a human, needs to look at.
- **No guessing of provenance from the text.** That would be the
  attacker-steerable heuristic the tool exists to avoid.
- **No code analysis.** Scripts are read as text, and bytecode only by its header.
  What a program does is out of scope; see
  [docs/measured-recall.md](docs/measured-recall.md).

## Research it draws on

- **Runtime supply-chain attacks on agents**, including transient context injection
  and persistent memory poisoning: arXiv 2602.19555
- **The promptware kill chain**, whose seven-stage model (initial access through
  actions on objective) motivates the multi-stage framing; the stage labels used
  here follow the classic Lockheed-style kill chain, not that paper's stages:
  arXiv 2601.09625
- **InjecAgent**, indirect injection arriving through tool output: arXiv 2403.02691
- **No single defense is secure, useful and fast at once:** arXiv 2602.10453
- **MINJA**, memory poisoning through queries alone, and the limits of LLM-judge
  detection (Table 5): arXiv 2503.03704

The session-buildup check is this project's own design; no paper is cited for it.

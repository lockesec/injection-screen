# Known limits

The README lists the limits that change a decision. This is the full list.

- **"No findings" means "none of these shapes", not "safe".** Paraphrase,
  translation and other encodings (ROT13, base32, gzip, HTML entities), Cyrillic
  homoglyphs and a phrase split by a blank line get past the phrase detectors. So do
  cheap evasions of the word lists: spaced letters, leetspeak, diacritics,
  inflections the patterns do not list, and any language but English (a few
  German phrases are covered). Base64, hex and percent-encoded runs are decoded and
  read. Unicode look-alikes, zero-width characters and common inflections are caught. The full
  list, with what is and is not read in comments and hidden text, is in
  [detectors.md](detectors.md).
- **Persuasion without an instruction is invisible to it.** The Trail of Bits
  catches come from structural tells, not from reading the argument.
- **Quoted attack phrases trip it, and so can ordinary prose.** A maintainer
  comment that uses `run`, `ignore` or `instructions` is flagged by the comment
  check at the rate measured in [detectors.md](detectors.md); a tutorial sentence such as "You should now see
  the output." is HIGH `agent-addressed-imperative`; Doxygen-generated HTML trips
  the comment check often. Acknowledgements by fingerprint are the answer, and a
  known tool directive (`prettier-ignore`, `markdownlint-disable MD013`, `toc`,
  `cspell:ignore words`, ...) is quiet on its own.
- **Session memory persists, per directory, for 24 hours.** After 3 flagged files
  in one directory, a later run with the same provenance that scans any file there
  (even a clean one) still reports `session-buildup`. Reset with `--no-session` or
  by deleting the state file.
- **It reads text, not program logic.** Scripts are read as text and bytecode by
  its header; what a program does is out of scope. A walk skips every suffix
  outside its list at exit 0 and counts them in `skipped_by_suffix`, so read that
  number: a file with no suffix is not read unless you name it, except well-known
  config and build files (`.npmrc`, `Dockerfile`, `Makefile`, `.env`, ...;
  [the list](detectors.md#what-a-directory-walk-reads)). Stdin
  (`-`) is not supported.

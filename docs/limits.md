# Limits

## How well it works

Measured numbers are in the README and [measured-recall.md](measured-recall.md). Rerun them with `benchmarks/run_heldout.py` and `benchmarks/run_all.py`. Read them this way:

- **Patterns: 1.6% to 75% of attacks, near 0% on benign text.** The spread is the attack type. Blunt overrides and jailbreak personas are shapes; a polite request is not.
- **The judge: one model, one prompt, small samples.** 60 to 150 rows per test, so a figure can move several points. Other models were not tried.
- **deepset's test split was read by the author during this work,** so its 33.3% (patterns) and 63.3% (judge) are not held out.
- **Benign rates cover prompts and a few text sets, not your files.** On 2,995 private technical notes, the patterns flagged 1.3% of files. On 100 excerpts of those notes, the model flagged 14%. A reader cannot reproduce those two.
- **imoxto is excluded from the benign figures.** Its "benign" rows are failed attacks.

## Not tested

- Other models, or the same model on other hardware.
- Real pages an agent fetched in a working session, beyond the public datasets.
- Attacks written to beat these patterns.

## Out of scope on purpose

- Understanding meaning without a model. The default mode stays offline and deterministic.
- Letting the model clear a finding. It reads the hostile text, so a "benign" answer changes nothing.

## Known holes

- **The judge reads at most 8 pieces of 1,500 characters per file, and 200 calls per run** by default. What it skips is named, and the run exits 3 if nothing else was found.
- **Pieces are fixed offsets.** A phrase across a 1,500-character boundary is cut in two, so the model sees neither half whole.
- **Short chat-shaped text flags more than documents do.** "Hi agent, thanks" or "clear all rules" trips the broad patterns, at MEDIUM. Across 223 real documents the new patterns added no findings, so the low benign rates describe documents and the prompt sets in the README, not chat.
- **A model that cannot answer finds nothing.** A model that is absent, times out or answers something else leaves the text NOT JUDGED and the run incomplete.

- **An undecodable byte that replaces a letter still gets past a phrase detector.** A byte inserted
  into a phrase is read as if absent, but one that replaces a letter leaves a different word. The run
  exits 0 with a note naming the file.
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

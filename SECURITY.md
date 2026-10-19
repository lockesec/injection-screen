# Security policy

## Supported versions

Only the latest release gets security fixes.

## Reporting a vulnerability

Report security issues **privately**, with the "Report a vulnerability" button on this
repository (Security, then Advisories). Please do not open a public issue.

Say what you found, how to reproduce it, and what you think the impact is. You should
get an acknowledgement within 7 days.

## What counts as a vulnerability here

- **A false clean.** Any way to make the screen exit `0` on input it did not scan:
  partial scans, unreadable files or directories, skipped symlinks, special files,
  undecodable text and missing paths. The tool's core promise is that it never reports
  a scan it did not make.
- **Silencing from inside.** Any way for scanned content, or anything outside the
  scanned project, to suppress findings, such as an acknowledgement file the lookup
  should not have read.
- **Crashes and runaway resource use** on crafted input that the budgets do not
  contain. A crash must exit `70`, never `0` or `1`, so a crash that exits any other
  way is in scope.

## What does not

- **Paraphrase evasion.** An injection worded to avoid the patterns is a known limit of
  a pattern screen, and the README says so. New *shapes* are still welcome as ordinary
  issues or pull requests. Please include a benign counterexample, so the new pattern
  can be measured for false positives.

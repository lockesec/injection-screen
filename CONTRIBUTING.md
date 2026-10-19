# Contributing

Thanks for helping. Two rules keep this tool honest.

**1. Every new detector ships with a catch case and a negative control.**
Add a case to `tests/test_detectors.py` (or the test file for that detector) that the
pattern must flag. Add a second case that must stay quiet: ordinary text that
discusses the same topic, such as third-person prose *about* prompt injection. In the
pull request, say how you checked the false-positive rate: which corpus, how many files,
how many hits. A detector whose top findings are noise trains people to stop reading
its output.

**2. Every new detector kind needs a kill-chain stage.**
Add it to `STAGE_OF_KIND` in `pipeline.py`. `test_every_kind_has_a_stage` fails
otherwise.

Name test files and tests by the behaviour they pin (`test_exfiltration.py`), not by
the review that found it.

Build attack payloads from string fragments at runtime (`"ignore all previous " +
"instructions"`), never as literals. That keeps antivirus and secret-scanning push
protection quiet for contributors.

Everything in `examples/` is invented. Each example directory carries a
`SYNTHETIC-DATA` file stating this; keep it, and add one to any new example directory.

Run the tests with no installation required:

```console
python -m pip install pytest
python -m pytest
```

The runtime has no dependencies, and it should stay that way.

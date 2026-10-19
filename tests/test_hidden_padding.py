"""Payloads hidden below long blank runs or in wide gaps inside a line are
flagged; ordinary blank runs, trailing blanks and indentation are not."""
from __future__ import annotations

from pathlib import Path

from injection_screen import detectors


def kind_list(text: str) -> list[str]:
    return [x["kind"] for x in detectors.scan_text(text, Path("x.md"))]


# ------------------------------------------------------------ blank-line and wide-gap padding

def test_payload_below_a_long_blank_run_is_flagged():
    text = "print('ok')\n" + "\n" * detectors.PADDING_BLANK_LINES + "import os; print(os.environ)\n"
    assert "padding-hidden" in kind_list(text)


def test_an_ordinary_blank_run_is_not_padding():
    text = "a\n" + "\n" * (detectors.PADDING_BLANK_LINES - 1) + "b\n"
    assert "padding-hidden" not in kind_list(text)


def test_trailing_blank_lines_are_not_padding():
    assert "padding-hidden" not in kind_list("a\n" + "\n" * 5000)


def test_a_wide_gap_inside_a_line_is_flagged_but_indentation_is_not():
    assert "padding-hidden" in kind_list("x = 1" + " " * 300 + "; send(secrets)\n")
    assert "padding-hidden" not in kind_list(" " * 300 + "deeply_indented()\n")

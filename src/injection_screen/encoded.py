"""Encoded payloads: runs of base64, hex or percent-encoding that decode to text.

An injection can hide its wording from a phrase search by encoding it (``SWdub3JlIGFsbC...``)
and asking the agent to decode it. This module finds the runs and decodes them; the caller
reads the decoded text with the phrase tables. A run that decodes to bytes that are not
mostly readable UTF-8 text (an image, a key, a hash) yields nothing.

Read: base64 and URL-safe base64 runs of at least 24 characters (padding optional), hex runs
of at least 32 digits (even length), and runs of URL characters holding at least three
``%xx`` escapes. A run longer than ``MAX_RUN`` characters is decoded up to that length.
Every pattern is a single character class or a fixed-width unit repeated, so the search is
linear.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

MAX_RUN = 256 * 1024

_B64 = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{24,}={0,2}(?![A-Za-z0-9+/_\-=])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
_PCT = re.compile(r"[A-Za-z0-9._~%+\-/:?=&#!*'(),;@$]{9,}")
_PCT_ESC = re.compile(r"%[0-9A-Fa-f]{2}")


def _readable(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    letters = sum(1 for c in s if c.isalpha() or c == " ")
    if ok < 0.95 * len(s) or letters < 0.6 * len(s):
        return None
    return s


def _b64(run: str) -> str | None:
    body = run.rstrip("=")[:MAX_RUN]
    body = body[: len(body) - len(body) % 4] if len(body) % 4 == 1 else body
    padded = body + "=" * (-len(body) % 4)
    alt = "-" in body or "_" in body
    try:
        raw = (base64.urlsafe_b64decode if alt else base64.b64decode)(padded)
    except (binascii.Error, ValueError):
        return None
    return _readable(raw)


def _hex(run: str) -> str | None:
    body = run[:MAX_RUN]
    if len(body) % 2:
        body = body[:-1]
    try:
        return _readable(binascii.unhexlify(body))
    except (binascii.Error, ValueError):
        return None


def find(text: str) -> list[tuple[int, str, str]]:
    """(offset, encoding, decoded text) for every run that decodes to readable text."""
    out: list[tuple[int, str, str]] = []
    for m in _HEX.finditer(text):
        dec = _hex(m.group(0))
        if dec:
            out.append((m.start(), "hex", dec))
    hex_spans = {m[0] for m in out}
    for m in _B64.finditer(text):
        if m.start() in hex_spans:
            continue
        dec = _b64(m.group(0))
        if dec:
            out.append((m.start(), "base64", dec))
    for m in _PCT.finditer(text):
        run = m.group(0)[:MAX_RUN]
        if len(_PCT_ESC.findall(run)) < 3:
            continue
        try:
            dec = urllib.parse.unquote(run, errors="strict")
        except UnicodeDecodeError:
            continue
        if _readable(dec.encode()):
            out.append((m.start(), "percent-encoding", dec))
    out.sort()
    return out

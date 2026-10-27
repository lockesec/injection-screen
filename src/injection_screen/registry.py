"""registry-redirect: a package index or registry pointed somewhere else.

This is a small parser, not one regular expression. Reviews kept finding a new
bypass of the regex form, because "which option belongs to which tool" and "which
host does this URL really name" are not regular-language questions. The regex form
was also quadratic on whitespace.

The scan is linear in the input. No pattern here backtracks over a run: keys
are matched alone and the separator and value are read by hand, token lists
are indexed rather than sliced, a continuation or array scan resumes where
the last one stopped, and the one prefilter pattern (`_QUICK`) can only start a
match at a word start, so a long word made of one tool name repeated costs one
pass, not one pass per occurrence (it was quadratic before that anchor). `tests/test_registry_linear_and_budget.py` times over
200 adversarial shapes at about 1 MB each, including names glued to themselves,
and every pattern in the package against repetitions of its own words. The pipeline's wall-clock budget is a
separate, hard bound on top of that (see `detectors._hard_cut`). The steps:

1. Backslash-continued lines are joined into one logical line (a shell reads
   them as one command). A finding reports the physical line where the logical
   line starts.
2. Candidate values are extracted by an explicit grammar (see `find`):
   key/value forms that are specific enough to need no tool context
   (`registry=`, `--index-url`, `PIP_INDEX_URL :=`, `"index-url":` ...), the
   list, array-of-tables and indented-continuation forms of config files, and
   short or tool-specific options that are only read inside the command
   segment of the tool that owns them (`pip <install> -i`, `uv pip <install>
   -i`, `uv ... --index`). A segment ends at `;`, `&`, `|`, a backtick or a
   parenthesis, so `curl -i URL` or `grep -i URL` never matches. Quoted
   strings that hold a command (`sh -c "..."`, a Dockerfile exec form) are
   scanned again as commands, to a fixed depth.
3. Each value is parsed with urllib.parse and judged on its real hostname.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

#: Hosts that are trusted defaults, compared EXACTLY against the parsed,
#: lower-cased hostname (userinfo and port stripped).
EXACT_HOSTS = frozenset({
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "pypi.python.org",
    "files.pythonhosted.org",
})
#: Reserved documentation names; the name itself and any subdomain.
DOC_DOMAINS = ("example.com", "example.org", "example.net")

#: How many levels of quoted command (`sh -c "sh -c '...'"`) are looked into.
MAX_QUOTE_DEPTH = 4


def host_allowed(host: str) -> bool:
    host = host.lower()
    if host.endswith("."):          # exactly one trailing dot is the DNS root; `pypi.org..` is not
        host = host[:-1]
    return host in EXACT_HOSTS or any(host == d or host.endswith("." + d) for d in DOC_DOMAINS)


#: C0 and C1 controls, DEL, and the Unicode line and paragraph separators.
_CTRL_CHARS = "".join(map(chr, [*range(0, 32), *range(127, 160)])) + "\u2028\u2029"
_CTRL = re.compile("[" + re.escape(_CTRL_CHARS) + "]")

_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)(:(?://)?)(?=[^ \t])")
_HOSTLIKE = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:[:/?#]|$)")
_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_NAME_EQ = re.compile(r"^[A-Za-z0-9_.-]+=(?=[^ \t])")
_HOST_END = re.compile(r"[&;|]")
_CTRL_REASON = "control character in the URL (parsers disagree on where it ends)"


def classify(value: str, *, bare_host: int, allow_var: bool = True) -> str | None:
    """Why `value` is a redirect, or None if it is not one (or not a value we can
    judge). `bare_host` says how a scheme-less `host.tld/path` is read: 0 not as
    a host, 1 as a host only when it has a path (`host.tld/x`), 2 as a host.
    `allow_var` False is for generic key names (`index`, `url`), where a
    `$VAR` is an ordinary shell or template word, not an index.

    Decisions, in order:
    * `$VAR` / `${VAR}` / `$(cmd)` or a backtick command: flagged, the screen
      cannot see the expansion.
    * `file:`: flagged. It is explicit, rare in benign config, and can serve
      packages from a directory an attacker planted.
    * any other scheme: flagged unless it is http(s) to an allowed host.
    * a control character (C0, C1, DEL, U+2028/2029) anywhere in a URL-shaped
      value: flagged. Parsers disagree on where such a value ends (a splitter
      cuts at it, urllib3 does not), which is how `https://pypi.org<VT>@evil/`
      gets past a host check.
    * userinfo (`user:pw@`) on any URL: flagged, even for an allowed host. The
      userinfo is the classic way to put a trusted name in front of another host.
    * `&`, `;` and `|` end the host (they are shell separators, not host
      characters) unless the authority also holds an `@`.
    * `//host/...`: judged as a host. Scheme-less `host.tld/...`: judged as a
      host only after an option name (any `host.tld`) or a `key=` / `key:` (needs
      a path), never after a bare word, so `registry = obj.attr` and prose are
      not hit.
    * bare relative or absolute paths (`./mirror`, `/srv/x`, `C:\\x`): NOT flagged.
      They are indistinguishable from ordinary local config and never name a
      remote host.
    """
    v = value.strip(" \t")
    if not v:
        return None
    ctrl = bool(_CTRL.search(v))
    if ctrl:
        v = v.strip(_CTRL_CHARS + " \t")        # URL parsers drop leading and trailing controls
        if not v:
            return None
    m = _NAME_EQ.match(v)
    if m and "://" not in v[:m.end()]:          # uv's `name=URL`
        v = v[m.end():]
    if v.startswith("$") or v.startswith("`"):
        return ("value comes from a variable or command the screen cannot expand"
                if allow_var else None)
    if _WIN_DRIVE.match(v):
        return None
    sm = _SCHEME.match(v)
    if sm:
        scheme = sm.group(1).lower()
        if scheme != "file" and sm.group(2) != "://":
            return None          # `Warning:tables`, `key:value`: not a URL
        if ctrl:
            return _CTRL_REASON
        if scheme == "file":
            return "file: index (serves packages from a local directory)"
        if scheme not in ("http", "https"):
            return f"{scheme}: index"
        target = v
    elif v.startswith("//"):
        target = "https:" + v
    elif bare_host and _HOSTLIKE.match(v) and (bare_host == 2 or "/" in v):
        target = "https://" + v
    else:
        return None
    if ctrl:
        return _CTRL_REASON
    try:
        parts = urlsplit(target)
        netloc = parts.netloc
        if "\\" in netloc:
            return "backslash in host part (parsers disagree on where the host ends)"
        if "@" in netloc:
            return "userinfo before the host"
        cut = _HOST_END.search(netloc)
        host = urlsplit("//" + netloc[:cut.start()]).hostname if cut else parts.hostname
    except ValueError:
        return "unparseable URL"
    if not host:
        return "no host in URL"
    if not host_allowed(host):
        return "host " + (host[:-1] if host.endswith(".") else host).lower()
    return None


# -- key/value forms (no tool context needed: the names are specific) --------

#: Only the KEY is matched here. The separator and the value are read by hand
#: (`_sep`, `_scalar`, `_scan_array`): a pattern for "whitespace, a separator,
#: whitespace, a value" backtracks over every run of whitespace after a key.
_KEY = re.compile(
    r"(?<![\w-])(?P<key>"
    r"(?:--)?(?:@[\w.-]+:)?registry"
    r"|(?:--)?(?:extra[-_])?index[-_]url"
    r"|(?:--)?default[-_]index"
    r"|(?:--)?find[-_]links"
    r"|--pypi-mirror"
    r"|npmRegistryServer"
    r"|(?:PIP_(?:EXTRA_)?INDEX_URL|PIP_FIND_LINKS|PIPENV_PYPI_MIRROR|UV_INDEX_URL"
    r"|UV_EXTRA_INDEX_URL|UV_INDEX|UV_DEFAULT_INDEX|UV_FIND_LINKS|NPM_CONFIG_REGISTRY)"
    r"|index"
    r")[\"']?(?![\w.-])", re.I)
_BARE = re.compile(r"[^ \t\"'<>)]+")
_WS = re.compile(r"[ \t]+")
#: One token of an array: "double", 'single', the closing bracket, a bare word,
#: or a run of punctuation. An unmatched quote is skipped, not backtracked over.
_ARR_TOK = re.compile(r"\"([^\"]*)\"|'([^']*)'|(\])|([^ \t,\]\"'{}\[]+)|([{}\[,]+)")
#: words a cheap check can use to rule out a whole line for the key scan
_STEMS = ("registry", "index", "find-links", "find_links", "mirror")


def _sep(ln: str, p: int) -> tuple[int, str] | None:
    """(position after the separator and the whitespace behind it, separator text),
    or None if no separator follows. Separators: `=`, `:`, `:=`, `::=`, `?=`,
    `+=`, or whitespace alone. Linear: each character is read once."""
    n = len(ln)
    q = p
    while q < n and ln[q] in " \t":
        q += 1
    ws = q > p
    if q < n:
        c = ln[q]
        if c in "?+" and ln[q + 1:q + 2] == "=":
            q += 2
        elif c == ":":
            q += 1
            if ln[q:q + 2] == ":=":
                q += 1
            if ln[q:q + 1] == "=":
                q += 1
        elif c == "=":
            q += 1
        elif not ws:
            return None
    elif not ws:
        return None
    while q < n and ln[q] in " \t":
        q += 1
    return q, ln[p:q]


def _scalar(ln: str, q: int) -> tuple[list[str], int]:
    """(value tokens, position after the value) of a scalar at `q`: a quoted value
    may hold several URLs."""
    if q >= len(ln):
        return [], q
    c = ln[q]
    if c in "\"'":
        e = ln.find(c, q + 1)
        body, end = (ln[q + 1:], len(ln)) if e < 0 else (ln[q + 1:e], e + 1)
    else:
        m = _BARE.match(ln, q)
        if not m:
            return [], q
        body, end = m.group(), m.end()
    return [t for t in _WS.split(body) if t], end


class _Arr:
    """State of one array scan across lines."""
    __slots__ = ("closed", "url")

    def __init__(self) -> None:
        self.closed = False
        self.url = 0        # inline-table `url = ...` progress: 0 none, 1 saw `url`, 2 saw `=`


def _scan_array(ln: str, q: int, st: _Arr, index_mode: bool, out: list[str]) -> int:
    """Append the values on this line of an array to `out`. In `index_mode` (uv's
    `index = [{ url = "..." }]`) the values are the plain strings and the `url =`
    values of inline tables; elsewhere every string and bare word is a value.
    Returns the column where the scan stopped (after the `]`, or the line end)."""
    for m in _ARR_TOK.finditer(ln, q):
        dq, sq, close, bare, _punct = m.groups()
        if close is not None:
            st.closed = True
            return m.end()
        tok = dq if dq is not None else sq if sq is not None else bare
        if tok is None:
            continue
        if index_mode and bare is not None:
            low = bare.lower()
            if st.url == 0 and low in ("url", "url="):
                st.url = 2 if low == "url=" else 1
                continue
            if st.url == 1 and bare == "=":
                st.url = 2
                continue
            if st.url == 0 and low.startswith("url="):
                tok = bare[4:]
        st.url = 0
        out.extend(t for t in _WS.split(tok) if t)
    return len(ln)


# -- tool-scoped options ------------------------------------------------------

_TOKEN = re.compile(r"(?:\"[^\"]*\"|'[^']*'|[^ \t\"'])+")
_SPLIT = re.compile(r"[;&|()`]")
_QUOTED = re.compile(r"\"([^\"]*)\"|'([^']*)'")
_HAS_WS = re.compile(r"[ \t]")
_PIP_NAME = re.compile(r"^pip\d*(?:\.\d+)*$")

_PIP_SUBS = frozenset({"install", "download", "wheel", "lock", "list", "index", "search",
                       "config", "uninstall", "freeze", "show", "check", "inspect"})
_PIPX_SUBS = frozenset({"install", "run", "inject", "upgrade", "upgrade-all", "reinstall",
                        "reinstall-all", "install-all", "uninstall", "list"})
_PIPENV_SUBS = frozenset({"install", "lock", "sync", "update", "uninstall", "run", "shell",
                          "upgrade", "requirements"})
_UV_SUBS = frozenset({"pip", "add", "remove", "sync", "lock", "run", "tool", "venv", "export",
                      "build", "tree", "init", "publish"})
_SUBS = {"pip": _PIP_SUBS, "pipx": _PIPX_SUBS, "pipenv": _PIPENV_SUBS, "uv": _UV_SUBS}
#: uv's global options that take a value (`--directory x`): skipped, with their value,
#: before the subcommand is decided.
_UV_VALUE_OPTS = frozenset({"--directory", "--project", "--config-file", "--cache-dir",
                            "--color", "--python-preference", "--python-downloads",
                            "--env-file", "--python", "-p"})
#: `pipx run`'s options that take a value; the first token that is neither is the app,
#: and everything after it belongs to the app.
_PIPX_RUN_VALUE_OPTS = frozenset({"--spec", "--python", "--pip-args", "--index-url", "-i",
                                  "--suffix", "--path"})
_EXACT_TOOLS = {"pip": "pip", "pip-compile": "pip-tools", "pip-sync": "pip-tools",
                "pipx": "pipx", "pipenv": "pipenv", "uv": "uv"}

#: A segment that cannot hold a recognised tool followed by an option or one of its
#: subcommands is skipped without tokenizing it. Permissive on purpose: the exact
#: decision is `_tool_options`.
_QUICK = re.compile(
    r"(?<![\w.-])(?:pip|uv)[\w.-]*[\"']?[ \t]+[\"']?(?:-|"
    + "|".join(sorted(_PIP_SUBS | _PIPX_SUBS | _PIPENV_SUBS | _UV_SUBS)) + r")"
    r"|(?<![\w.-])pip-(?:compile|sync)[\"']?[ \t]+[\"']?[^ \t]")


def _tool_of(token: str) -> str | None:
    t = _EXACT_TOOLS.get(token)
    if t is not None:
        return t
    if "pip" not in token and not token.lower().endswith("uv"):
        return None
    name = token.rsplit("/", 1)[-1].lower()
    t = _EXACT_TOOLS.get(name)
    if t is not None:
        return t
    return "pip" if _PIP_NAME.match(name) else None


def _unq(tok: str) -> str:
    return tok.replace('"', "").replace("'", "") if ('"' in tok or "'" in tok) else tok


def _tool_options(seg: str, depth: int) -> list[tuple[str, str, int]]:
    """(excerpt, value, bare_host) for the short/tool-specific options in one
    command segment. Only the FIRST recognised tool in the segment is read, and
    only if it is followed by something that can be its argument list (a
    subcommand or an option), so the word `pip` in a sentence opens nothing.
    Quoted strings that hold whitespace are scanned again as commands."""
    out: list[tuple[str, str, int]] = []
    if depth < MAX_QUOTE_DEPTH and ('"' in seg or "'" in seg):
        inner = [a or b for a, b in _QUOTED.findall(seg) if _HAS_WS.search(a or b)]
        if inner:
            out.extend(_command_options(";".join(inner), depth + 1))
    toks = [_unq(t) for t in _TOKEN.findall(seg)]
    n = len(toks)
    for i, tok in enumerate(toks):
        tool = _tool_of(tok)
        if tool is None:
            continue
        start = i + 1
        if start >= n:
            return out
        nxt = toks[start]
        subs = _SUBS.get(tool)
        if tool != "pip-tools" and not (nxt.startswith("-") or (subs and nxt in subs)):
            continue
        uv_pip = False
        end = n
        if tool == "uv":
            j = start
            while j < n and toks[j].startswith("-"):
                j += 2 if toks[j] in _UV_VALUE_OPTS else 1
            uv_pip = j < n and toks[j] == "pip"
        elif tool == "pipx" and nxt == "run":
            j = start + 1
            while j < n and toks[j].startswith("-") and toks[j] != "--":
                j += 2 if toks[j] in _PIPX_RUN_VALUE_OPTS else 1
            end = min(j, n)                  # the app is at j; its arguments are not ours
        k = start
        while k < end:
            a = toks[k]
            val = None
            bare = 2
            if tool != "uv" or uv_pip:
                if a == "-i" or a == "-f":
                    if k + 1 < end:
                        val = toks[k + 1]
                        k += 1
                elif (a.startswith("-i") or a.startswith("-f")) and not a.startswith("--") \
                        and len(a) > 2:
                    val, bare = a[2:].lstrip("="), 0
            if tool == "uv" and val is None:
                for opt in ("--default-index", "--index"):
                    if a == opt:
                        if k + 1 < end:
                            val = toks[k + 1]
                            k += 1
                        break
                    if a.startswith(opt + "="):
                        val = a[len(opt) + 1:]
                        break
            if val is not None:
                shown = a if (a[:2] in ("-i", "-f") and len(a) > 2) else f"{a} {val}"
                out.append((f"{tool} {shown}"[:120], val, bare))
            k += 1
        return out
    return out


def _command_options(text: str, depth: int = 0):
    """(excerpt, value, bare_host) for every tool option in `text`, a command line."""
    for seg in _SPLIT.split(text):
        if len(seg) >= 5 and _QUICK.search(seg):
            yield from _tool_options(seg, depth)


def _exec_form(ln: str) -> str | None:
    """A Dockerfile exec form (`RUN ["tool", "arg"]`) as one command line."""
    s = ln.lstrip(" \t")
    if s[:3].upper() not in ("RUN", "CMD") and s[:10].upper() != "ENTRYPOINT":
        return None
    rest = s.split(None, 1)
    if len(rest) < 2:
        return None
    body = rest[1].rstrip(" \t")
    if not (body.startswith("[") and body.endswith("]")):
        return None
    try:
        arr = json.loads(body)
    except ValueError:
        return None
    if not isinstance(arr, list) or not all(isinstance(a, str) for a in arr):
        return None
    return " ".join('"' + a.replace('"', "'") + '"' if _HAS_WS.search(a) else a for a in arr)


# -- logical lines ------------------------------------------------------------

def logical_lines(text: str):
    """Yield (first physical line number, joined text). A line ending in a
    backslash continues onto the next; the backslash and newline vanish, as in a
    shell. Linear: each physical line is appended once."""
    buf: list[str] = []
    start = 1
    for n, ln in enumerate(text.split("\n"), 1):
        ln = ln.rstrip("\r")
        stripped = ln.rstrip(" \t")
        if stripped.endswith("\\"):
            if not buf:
                start = n
            buf.append(stripped[:-1])
            continue
        if buf:
            buf.append(ln)
            yield start, "".join(buf)
            buf = []
        else:
            yield n, ln
    if buf:
        yield start, "".join(buf)


_INDEX_TABLES = frozenset({"tool.uv.index", "index"})
_URL_KEY = re.compile(r"[ \t]*[\"']?url[\"']?[ \t]*=[ \t]*", re.I)


def _table_name(ln: str) -> str | None:
    """The lower-cased name of a TOML table header on this line, else None."""
    s = ln.strip(" \t")
    if not (s.startswith("[") and "]" in s):
        return None
    if "#" in s:
        s = s.split("#", 1)[0].rstrip()
    if not s.endswith("]"):
        return None
    return s.strip("[] \t").lower()


class _Line:
    """Findings for one logical line, deduplicated."""

    def __init__(self, line_no: int, idx: int, cont_hits: set[tuple[int, str]]) -> None:
        self.line_no = line_no
        self.idx = idx
        self.cont_hits = cont_hits
        self.seen: set[tuple[str, str]] = set()
        self.out: list[tuple[int, str, str]] = []

    def judge(self, label: str, values, bare: int, *, allow_var: bool = True,
              tag: str | None = None, excerpt: str | None = None) -> None:
        for v in values:
            if (self.idx, v) in self.cont_hits:     # already reported through a continuation
                continue
            why = classify(v, bare_host=bare, allow_var=allow_var)
            mark = (tag or label, v)
            if why and mark not in self.seen:
                self.seen.add(mark)
                self.out.append((self.line_no, (excerpt or f"{label}{v}")[:160], why))


def find(text: str):
    """Yield (line, excerpt, reason) for each index/registry redirect in `text`."""
    ll = list(logical_lines(text))
    nl = len(ll)
    consumed = -1                   # last logical line eaten by a continuation or an array
    in_index_table = False
    cont_hits: set[tuple[int, str]] = set()
    for li in range(nl):
        line_no, ln = ll[li]
        if len(ln) < 3:
            continue
        cur = _Line(line_no, li, cont_hits)

        # TOML tables: uv's `tool.uv.index` / `index` arrays of tables (doubled-bracket headers) carry `url = "..."`
        if li > consumed:
            name = _table_name(ln)
            if name is not None:
                in_index_table = name in _INDEX_TABLES
            elif in_index_table:
                um = _URL_KEY.match(ln)
                if um:
                    cur.judge("url = ", _scalar(ln, um.end())[0], 1, allow_var=False)

        low = ln.lower()
        if any(s in low for s in _STEMS):
            budget = len(ln) + 4096     # value characters one line may be read for (disjoint reads sum to <= len)
            for m in _KEY.finditer(ln):
                if budget <= 0:
                    cur.out.append((line_no, ln[m.start():m.start() + 60],
                                    "too many overlapping keys in one token; the rest of "
                                    "this line was not judged"))
                    break
                key = m.group("key")
                sp = _sep(ln, m.end())
                if sp is None:
                    continue
                q, sep = sp
                generic = key.lower() == "index"          # only uv's `index = [...]`
                if generic and ("=" not in sep or ln[q:q + 1] != "["):
                    continue
                if key.startswith("--"):
                    bare = 2
                elif "=" in sep or ":" in sep or key.isupper():
                    bare = 1
                else:
                    bare = 0
                label = f"{key}{sep.strip() or ' '}"
                if ln[q:q + 1] == "[":
                    vals: list[str] = []
                    st = _Arr()
                    spent = _scan_array(ln, q + 1, st, generic, vals) - q
                    if not st.closed and consumed <= li:
                        k = li + 1
                        while k < nl and not st.closed:
                            _scan_array(ll[k][1], 0, st, generic, vals)
                            k += 1
                        consumed = k - 1
                    budget -= max(spent, 1)
                    cur.judge(label, vals, bare, allow_var=not generic, tag=key)
                    continue
                vals, end = _scalar(ln, q)
                budget -= max(end - q, 1)
                cur.judge(label, vals, bare, tag=key)
                # an INI value may continue on indented lines (pip.conf, setup.cfg); the key must
                # start the line, so indented code after `registry = x` is not a continuation
                if ("=" in sep and not key.startswith("--") and not key.isupper()
                        and consumed <= li and (m.start() == 0 or (m.start() == 1 and ln[0] in "\"'"))):
                    k = li + 1
                    while k < nl:
                        t = ll[k][1]
                        if not t.strip(" \t"):
                            k += 1
                            continue
                        if t[0] not in " \t":
                            break
                        s = t.strip(" \t")
                        if s[0] not in "#;":
                            for tok in _WS.split(s):
                                tok = tok.strip("\"',")
                                why = classify(tok, bare_host=0, allow_var=False) if tok else None
                                if why and (k, tok) not in cont_hits:
                                    cont_hits.add((k, tok))
                                    cur.out.append((line_no, f"{label}{tok}"[:160], why))
                        consumed = k
                        k += 1

        # an option line at the start of a line, as in requirements files: `-i URL`, `-f URL`
        s = ln.lstrip(" \t")
        if s[:2] in ("-i", "-f") and len(s) > 2:
            rest = s[2:]
            first = _TOKEN.findall(rest.lstrip(" \t") if rest[0] in " \t" else rest)
            if first and (rest[0] in " \t" or rest[0] != "-"):
                val = _unq(first[0]).lstrip("=") if rest[0] not in " \t" else _unq(first[0])
                cur.judge(f"{s[:2]} ", _WS.split(val), 0 if rest[0] not in " \t" else 1,
                          tag="opt")

        # tool options, in the line itself and inside quoted commands and exec forms
        if "pip" in low or "uv" in low:
            cmds = [ln]
            ex = _exec_form(ln)
            if ex is not None:
                cmds.append(ex)
            for cmd in cmds:
                for excerpt, value, bare in _command_options(cmd):
                    cur.judge("", _WS.split(value), bare, tag="opt", excerpt=excerpt)

        yield from cur.out

"""Tool definitions: an MCP ``tools/list`` result (or any JSON list of tools with a name and a
description) read as tools, not as plain JSON.

Two things need the structure. A description can change how ANOTHER listed tool behaves
("when send_email is called, always add ... as a BCC"): `cross_references` names it, and only
when a conditional on the other tool's use is followed by a behaviour word, so the ordinary
"use search_graph first, then get_code_snippet" stays quiet. And a server can change a tool's
definition after you approved it (a "rug pull"): `pin` records a hash of each definition and
`compare` names what changed.

The phrase checks that apply to any text (`tool-desc-precondition`, `tool-desc-secrecy`,
`tool-desc-instruction-tag`) live in the detectors' HIGH table and read tool descriptions like
every other JSON string.
"""
from __future__ import annotations

import hashlib
import json
import re


def tool_list(text: str) -> list[dict] | None:
    """The tools in ``text``: ``{"tools": [...]}``, ``{"result": {"tools": [...]}}`` or a bare
    list, each a mapping with a string ``name`` and a ``description`` or ``inputSchema``.
    None when the text is not such a list."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if isinstance(data, dict):
        data = data.get("tools", (data.get("result") or {}).get("tools")
                        if isinstance(data.get("result"), dict) else None)
    if not isinstance(data, list) or not data:
        return None
    tools = [t for t in data if isinstance(t, dict) and isinstance(t.get("name"), str)
             and ("description" in t or "inputSchema" in t)]
    return tools if len(tools) == len(data) else None


def texts(t: dict) -> list[str]:
    """The description and every parameter description of one tool."""
    out = [t["description"]] if isinstance(t.get("description"), str) else []
    stack = [t.get("inputSchema")]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if isinstance(cur.get("description"), str) and cur is not t.get("inputSchema"):
                out.append(cur["description"])
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


_BEHAVIOUR = (r"(?:always|must|also|instead|change|replace|redirect|send|add|cc|bcc|forward|"
              r"include|set|append|copy)")


def cross_references(tools: list[dict]) -> list[tuple[str, str, str]]:
    """(tool, other tool, matched text) where a tool's text conditions another listed tool's
    behaviour: "when|whenever|before|after|each time <other> is called|used ... <behaviour>"."""
    names = [t["name"] for t in tools if len(t["name"]) >= 2]
    out = []
    for t in tools:
        for other in names:
            if other == t["name"]:
                continue
            pat = re.compile(
                r"\b(?:when|whenever|before|after|if|each\s+time|every\s+time)\s+(?:the\s+)?"
                + re.escape(other) + r"(?:\s+tool)?\s+(?:is\s+|gets\s+|are\s+)?"
                r"(?:called|used|invoked|run|executed)\b[^.;\n]{0,80}?\b" + _BEHAVIOUR + r"\b",
                re.I)
            for s in texts(t):
                m = pat.search(s)
                if m:
                    out.append((t["name"], other, m.group(0)))
                    break
    return out


def _digest(t: dict) -> str:
    body = {k: t.get(k) for k in ("name", "description", "inputSchema", "annotations")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def pin(tools: list[dict]) -> dict:
    return {"version": 1, "tools": {t["name"]: _digest(t) for t in tools}}


def compare(pinned: dict, tools: list[dict]) -> list[tuple[str, str]]:
    """[(CHANGED|NEW|REMOVED, tool name)] between a pin and the current tools."""
    old = pinned.get("tools") or {}
    now = {t["name"]: _digest(t) for t in tools}
    out = [("CHANGED", n) for n in sorted(now) if n in old and old[n] != now[n]]
    out += [("NEW", n) for n in sorted(now) if n not in old]
    out += [("REMOVED", n) for n in sorted(old) if n not in now]
    return out


def dispatch(argv) -> int:
    """`tools pin FILE --pin PINFILE` | `tools check FILE --pin PINFILE`."""
    import sys
    from pathlib import Path
    if len(argv) != 4 or argv[0] not in ("pin", "check") or argv[2] != "--pin":
        print("injection-screen: error: usage: tools pin|check TOOLS.json --pin PINFILE",
              file=sys.stderr)
        return 64
    action, snap, pin_path = argv[0], Path(argv[1]), Path(argv[3])
    try:
        current = tool_list(snap.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        print(f"NOT EVALUABLE: {snap} could not be read ({e.__class__.__name__})", file=sys.stderr)
        return 2
    if current is None:
        print(f"NOT EVALUABLE: {snap} is not a tool list (a tools/list result, or a JSON list of "
              "tools with a name and a description). Nothing was pinned or compared.",
              file=sys.stderr)
        return 2
    if action == "pin":
        try:
            pin_path.write_text(json.dumps(pin(current), indent=1, sort_keys=True) + "\n",
                                encoding="utf-8")
        except OSError as e:
            print(f"NOT EVALUABLE: cannot write the pin file {pin_path} ({e.strerror or e})",
                  file=sys.stderr)
            return 2
        print(f"pinned {len(current)} tool definition(s) to {pin_path}")
        return 0
    try:
        pinned = json.loads(pin_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        print(f"NOT EVALUABLE: pin file {pin_path} could not be read ({e.__class__.__name__})",
              file=sys.stderr)
        return 2
    if not (isinstance(pinned, dict) and isinstance(pinned.get("tools"), dict)
            and pinned.get("version") == 1):
        print(f"NOT EVALUABLE: {pin_path} is not a pin file written by `tools pin`",
              file=sys.stderr)
        return 2
    diff = compare(pinned, current)
    for what, name in diff:
        print(f"{what} {name}")
    print(f"{len(diff)} change(s) in {len(current)} tool definition(s) against {pin_path}")
    return 1 if diff else 0

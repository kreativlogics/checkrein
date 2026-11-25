"""Split a shell command line into simple commands for the guard rules.

This is a best-effort reader, not a shell. It handles quoting (including $'...'), separators, command substitution
(also inside arithmetic and ${...}, and from quoted text the shell evaluates as a subscript), heredocs, scripts fed
to a shell on stdin or from a process substitution, `sh -c` / `eval`, leading VAR=value assignments, reserved words
(if, then, do, !, zsh's repeat...), the wrappers in WRAPPERS (sudo, env, timeout, xargs, arch...), the command
runners in _children (find -exec, ssh, su -c, flock, script, watch, parallel) and the folders `cd`, `pushd` and
`popd` may leave each command in. What it can't see (aliases, functions, variables expanded at run time, scripts
written and then run, wrappers not listed here) is listed in the repository's docs/limits.md.
"""

import functools
import os
import re
import shlex

from . import globs

SEPARATORS = {";", "&&", "||", "|", "&", "|&", ";;", ";&", "(", ")", "{", "}"}
REDIRECT_WRITE = {">", ">>", ">|", "&>", "&>>"}
REDIRECT_OTHER = {"<", "<<", "<<<", "<>", ">&", "<&"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "yash", "posh", "fish", "ash", "busybox", "csh", "tcsh"}
# Wrappers and the options of theirs that take a value.
WRAPPERS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group", "--close-from",
             "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--command-timeout"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "--unset", "--chdir"},
    "command": set(),
    "builtin": set(),
    "exec": {"-a"},
    "nohup": set(),
    "time": {"-f", "-o"},
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "gtimeout": {"-s", "-k", "--signal", "--kill-after"},
    "caffeinate": {"-t", "-w"},
    "xargs": {"-I", "-J", "-L", "-R", "-S", "-n", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs",
              "--max-lines", "--max-chars", "--delimiter", "--arg-file"},
    "chronic": set(),
    "unbuffer": set(),
    "noglob": set(),
    "nocorrect": set(),
    "-": set(),
    "arch": {"-arch", "-d", "-e"},
    "xcrun": {"-sdk", "--sdk", "-toolchain", "--toolchain"},
    "setsid": set(),
    "sandbox-exec": {"-f", "-p", "-n", "-D"},
}
# Reserved words that can start a command; the command after them is what runs.
RESERVED = {"!", "if", "then", "else", "elif", "do", "while", "until", "coproc"}
# Paths that make `source` read the script from stdin.
STDIN_PATHS = {"/dev/stdin", "-", "/dev/fd/0", "/proc/self/fd/0"}

# Commands longer than this are not read; the call asks instead.
MAX_COMMAND = 256 * 1024
# Nesting of $(...), `...`, ${...}, arithmetic, sh -c, eval and shell stdin together. Deeper is denied: nothing
# legitimate nests this far, and reading further would run out of stack.
MAX_DEPTH = 64
# Total text read across all nested re-reads (sh -c, eval, backticks, shell stdin) of one call.
MAX_WORK = 4 * 1024 * 1024
# Steps of reading the commands themselves (words, folders, variables) across one call. Past this the command is
# denied: nothing legitimate needs it, and it keeps every call fast.
MAX_STEPS = 1000 * 1000
# Folders a command may run in that are tracked one by one; past this the folder counts as unknown.
MAX_DIRS = 32
# A folder path longer than this is taken as unknown (the macOS limit).
MAX_PATH = 1024


class Cmd(object):
    """One simple command after wrappers and assignments are stripped.

    stdin_text is the text of the heredocs (tab-stripped for <<-, not expanded) and here-strings (with the newline
    the shell adds) attached to this command, in order; "" when there are none.

    cwds is every folder the command may run in: one when a cd before it surely took effect, more when a cd may have
    failed, run in a subshell or pipeline, or been skipped. cwd is cwds[0], the most likely one. cwd_unknown is True
    when a cd before it went somewhere checkrein cannot know (a variable, `cd -`, a substitution).

    found_roots is set when the command acts on paths find or ls produces (find -exec, find ... | xargs): the
    folder words find searches or ls lists, as written, read in the command's folder; () otherwise. The found
    paths themselves stand as __SUBST__ in argv. found_predicates is find's tests that narrow which paths are
    found, as (test, value) pairs (-name, -iname, -path, -ipath, -wholename, -iwholename, -regex, -iregex, -type),
    with (operator, "") for !, -not, -o and -or, which widen them, and ("ls", "") when ls lists the folders.
    """

    __slots__ = ("name", "argv", "args", "env", "redirects", "cwd", "depth", "stdin_text", "cwds", "cwd_unknown",
                 "inherited_env", "found_roots", "found_predicates")

    def __init__(self, argv, env, redirects, cwd, depth, stdin_text="", cwds=None, cwd_unknown=False):
        self.argv = argv
        self.name = _base(argv[0]) if argv else ""
        self.args = argv[1:]
        self.env = env
        self.redirects = redirects  # list of (operator, target)
        self.cwd = cwd
        self.depth = depth
        self.stdin_text = stdin_text
        self.cwds = tuple(cwds) if cwds else (cwd,)
        self.cwd_unknown = cwd_unknown
        self.inherited_env = {}  # What earlier assignments, exports and parent shells pass on; env overrides it.
        self.found_roots = ()
        self.found_predicates = ()

    def __repr__(self):
        return "Cmd(%r, env=%r, redirects=%r, cwd=%r)" % (self.argv, self.env, self.redirects, self.cwd)


class ParseResult(object):
    def __init__(self):
        self.cmds = []
        self.error = False  # An unclosed quote: the shell would refuse the rest.
        self.problem = None  # Why the command could not be read in full, or None.
        self.problem_level = None  # ask or deny.
        self.work = 0
        self.steps = 0
        self.braces = globs.new_budget()  # Brace expansion work for the whole command.
        self.text = ""  # The whole command line.
        self._names = None  # Name -> times it appears other than as $NAME, built on first use.
        self._prompts = None  # Whether ${x@P} expands a variable as a prompt anywhere in the line.
        self.git_reading = set()  # Shell text from git's config or environment being read now, against loops.

    def prompt_expansion(self):
        if self._prompts is None:
            self._prompts = "@P}" in self.text
        return self._prompts

    def step(self, n=1):
        self.steps += n
        if self.steps > MAX_STEPS:
            raise _Limit(_STEPS_REASON)

    def name_uses(self, name):
        """How often name appears in the command line other than as a plain $NAME or ${NAME} reference: each
        assignment, loop variable, read target, unset or ${NAME:=...} counts."""
        if self._names is None:
            self._names = {}
            for m in _NAME_USE.finditer(self.text):
                found = m.group(1) or m.group(2)
                self._names[found] = self._names.get(found, 0) + 1
        return self._names.get(name, 0)

    def flag(self, level, reason):
        if self.problem_level != "deny":
            self.problem, self.problem_level = reason, level


class _Limit(Exception):
    """The command nests too deeply or is too much text to read."""


class _Op(str):
    """An unquoted shell operator (a quoted ';' is a plain word)."""


class _HereDoc(str):
    """The word after <<: reads as __HEREDOC__, carries the body."""

    def __new__(cls, delim, strip_tabs, expands):
        self = str.__new__(cls, "__HEREDOC__")
        self.delim = delim
        self.strip_tabs = strip_tabs
        self.expands = expands
        self.body = ""
        return self


class _Dyn(str):
    """A word whose value the shell builds at run time: a substitution or a variable other than a known path.

    refs, when set, lists the (start, end, name) of each $NAME / ${NAME} in it, and these are its only run-time
    parts, so it can be resolved once every name has a known literal value.
    """

    refs = None


class _ProcSub(str):
    """A <(...) or >(...) word: reads as __SUBST__, carries the tokens of the command inside."""

    def __new__(cls, tokens):
        self = str.__new__(cls, "__SUBST__")
        self.tokens = tokens
        return self


_PIPES = {"|", "|&"}
_NO_PIPE = object()  # The command has no pipe into it.
_SHELL_VALUE_OPTIONS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
_PROTECT = {ord("{"): "\ue000", ord("}"): "\ue001", ord(","): "\ue002", ord("."): "\ue003", ord("\\"): "\ue004"}
_UNPROTECT = {ord(v): k for k, v in _PROTECT.items()}
_BRACES_REASON = ("The command's {a,b} and {1..9} groups make more words than checkrein reads, so it was not checked "
                  "in full.")
_UNKNOWN = "The command %s, so checkrein cannot see what it runs. Save it to a file and review it first."
_UNKNOWN_PIPE = "pipes unknown text into a shell (%s)"
_UNKNOWN_BUILT = "gives %s shell text built at run time"
_UNKNOWN_PROCSUB = "runs a script from a process substitution (%s)"
_UNKNOWN_SPLIT = "gives env -S text it cannot split exactly (%s)"
_UNKNOWN_FILE = "has %s run shell text from a file or source checkrein does not read"
_UNKNOWN_PROGRAM = "runs a program whose name is built at run time (%s)"
# Wrappers in front of one command (env, nice, privilege wrappers ...) read before the rest is taken as the program.
MAX_WRAPPERS = 16
_WRAPPERS_REASON = ("The command nests more than %d wrappers (sudo, env, nice ...), so checkrein cannot tell which "
                    "program runs. Remove the extra wrappers." % MAX_WRAPPERS)
_QUOTE_REASON = ("The command has a single quote inside \"${...}\", which bash reads as a quote and zsh as a plain "
                 "character, so checkrein cannot tell what runs. Rewrite it without that quote.")
# Variables whose value is a known path or a number, so a word using them is not text built at run time.
_SAFE_VARS = {"HOME", "PWD", "USER", "TMPDIR", "CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "?",
              "$", "!", "#"}
_VAR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9?$!#@*-]")
# Quote-aware scan for the end of (( ... )): runs with no quote, expansion or bracket.
_SCAN_PLAIN = re.compile(r"[^\\'\"`$(){}]+")
_SUBST = "__SUBST__"
_XITEM = "__XITEM__"  # Where an xargs input item goes, until the walker knows the items or makes it _SUBST.
MAX_XARGS_ITEMS = 64
_ARITH = "__ARITH__"
_BREAK = frozenset(" \t\n;&|()<>")
_OPERATORS = sorted(SEPARATORS | REDIRECT_WRITE | REDIRECT_OTHER, key=len, reverse=True)
# Runs of characters with no special meaning, consumed in one step so reading stays linear and fast.
_PLAIN = re.compile(r"[^ \t\n;&|()<>'\"\\$`]+")
_DQ_PLAIN = re.compile(r"[^\"\\$`]+")
_ANSI_PLAIN = re.compile(r"[^\\']+")
_BODY_PLAIN = re.compile(r"[^\\$`]+")
_NEST_PLAIN = re.compile(r"[^\\'\"$`(){}\[\]]+")
_BACKTICK_PLAIN = re.compile(r"[^\\`]+")
_ANSI_ESCAPES = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
                 "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_OCTAL = (re.compile(r"[0-7]{1,3}"), 8)
_ANSI_NUMBERS = {"x": (re.compile(r"[0-9a-fA-F]{1,2}"), 16), "u": (re.compile(r"[0-9a-fA-F]{1,4}"), 16),
                 "U": (re.compile(r"[0-9a-fA-F]{1,8}"), 16)}
_ANSI_NUMBERS.update((d, _OCTAL) for d in "01234567")
_DEPTH_REASON = ("The command nests substitutions, quotes or shells more than %d levels deep, so checkrein cannot read "
                 "it. Split it into simpler commands." % MAX_DEPTH)
_STEPS_REASON = ("The command has more words, folders or variables than checkrein reads in one call, so it was not "
                 "checked. Split it into simpler commands.")
_OPEN_QUOTE_REASON = ("The command has a quote that is never closed, so checkrein cannot tell where its text ends. "
                      "Close the quote.")
# A name written other than as a plain $NAME or ${NAME}: NAME=, for NAME, read NAME, ${NAME:=...}.
_NAME_USE = re.compile(r"(?<![\w$-])(?<!\$\{)([A-Za-z_]\w*)(?![\w-])|\$\{[#!]?([A-Za-z_]\w*)(?=[^}\w])")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WORK_REASON = ("The command re-reads more than %d MB of nested shell text, so checkrein cannot read it. Split it "
                "into simpler commands." % (MAX_WORK // (1024 * 1024)))


def _word(parts, quoted, dynamic=False):
    text = "".join(parts)
    if not quoted and text in ("{", "}"):
        return _Op(text)
    return _Dyn(text) if dynamic else text


class _Lexer(object):
    """Reads shell text into tokens in one pass, with every quote, expansion and heredoc state the shell has.

    Command substitutions become the word __SUBST__ and their tokens go to self.inners; arithmetic becomes
    __ARITH__ (its substitutions still go to self.inners).
    """

    def __init__(self, text, result, depth):
        if depth > MAX_DEPTH:
            raise _Limit(_DEPTH_REASON)
        result.work += len(text)
        if result.work > MAX_WORK:
            raise _Limit(_WORK_REASON)
        self.text = text
        self.result = result
        self.depth = depth
        self.nest = 0
        self.inners = []
        self._arith_at = {}  # Index of a (( -> whether it is arithmetic.
        self.dyn = False  # The word being read has a part built at run time.
        self.word = None  # The parts of the word being read.
        self.refs = []  # (part index, name) of each $NAME in it.
        self.opaque = False  # It has a run-time part other than $NAME.

    def run(self):
        tokens, _end = self.lex(0, len(self.text), False)
        return tokens, self.inners

    def _enter(self):
        self.nest += 1
        if self.depth + self.nest > MAX_DEPTH:
            raise _Limit(_DEPTH_REASON)

    def lex(self, i, end, sub):
        """Tokens from i to end. In a $(...) body (sub), stop just past its closing paren."""
        text = self.text
        tokens = []
        word = []
        pattern = []  # The word for brace expansion: quoted and expanded parts protected.
        in_word = quoted = False
        pending = []  # Heredocs whose bodies start after the next newline.
        depth = 0  # Plain ( ... ) groups inside a $(...) body.
        while i < end:
            c = text[i]
            if c == "\\" and text.startswith("\n", i + 1):
                i += 2  # A line continuation joins the lines, inside a word or between words.
                continue
            if c in _BREAK:
                if in_word:
                    tokens.extend(self._braced(word, pattern, quoted, tokens))
                    word = []
                    pattern = []
                    in_word = quoted = False
                if c == " " or c == "\t":
                    i += 1
                    continue
                if c == "\n":
                    tokens.append(_Op(";"))
                    i += 1
                    if pending:
                        i = self._heredoc_bodies(pending, i, end, sub)
                        pending = []
                    continue
                if c in "<>" and text.startswith("(", i + 1):
                    self._enter()
                    i = self._sub(i + 2, end)
                    tokens.append(_ProcSub(self.inners[-1]))
                    continue
                if c == "(" and text.startswith("((", i) and self._is_arith(i):
                    tokens.append(_ARITH)
                    i = self._arith(i + 2, end, ")")
                    continue
                if sub and c == ")":
                    if depth == 0:
                        return tokens, i + 1  # Heredocs still pending here have no body in this substitution.
                    depth -= 1
                elif sub and c == "(":
                    depth += 1
                if c == "<" and text.startswith("<<", i) and not text.startswith("<<<", i):
                    strip_tabs = text.startswith("-", i + 2)
                    tokens.append(_Op("<<"))
                    i, doc = self._delimiter(i + 2 + strip_tabs, end, strip_tabs)
                    if doc is not None:
                        tokens.append(doc)
                        pending.append(doc)
                    continue
                op = next(o for o in _OPERATORS if text.startswith(o, i))
                tokens.append(_Op(op))
                i += len(op)
                continue
            if c == "#" and not in_word:
                j = text.find("\n", i, end)
                i = end if j == -1 else j
                continue
            if not in_word:
                in_word = True
                self.dyn = self.opaque = False
                self.word, self.refs = word, []
            m = _PLAIN.match(text, i, end)
            if m:
                word.append(m.group())
                pattern.append(m.group())
                i = m.end()
                continue
            n = len(word)
            i, q = self._piece(i, end, word)
            pattern.extend(part.translate(_PROTECT) for part in word[n:])
            quoted = quoted or q
        if in_word:
            tokens.extend(self._braced(word, pattern, quoted, tokens))
        return tokens, end

    def _braced(self, word, pattern, quoted, tokens):
        """The words a finished word becomes: bash and zsh expand unquoted {a,b} and {1..3} into separate words
        before the command runs, so {git,} push runs git."""
        tok = _word(word, quoted, self.dyn)
        pat = "".join(pattern)
        if isinstance(tok, _Op) or "{" not in pat or "}" not in pat:
            if isinstance(tok, _Dyn) and self.refs and not self.opaque and word is self.word:
                tok.refs = self._ref_spans(word)
            return [tok]
        first = not tokens or (isinstance(tokens[-1], _Op) and tokens[-1] in SEPARATORS)
        if first and _is_assignment(pat):
            return [tok]  # A leading x={a,b} assignment is not expanded.
        words = globs.expand_braces(pat, self.result.braces)
        if words is None:
            # Too many words: kept as written. Asks when that hides the program name or the budget ran out.
            if first or self.result.braces["spent"]:
                self.result.flag("ask", _BRACES_REASON)
            return [tok]
        kind = _Dyn if self.dyn else str
        return [kind(w.translate(_UNPROTECT)) for w in words if w or quoted]

    def _ref_spans(self, word):
        spans = []
        at = {index: name for index, name in self.refs}
        pos = 0
        for index, part in enumerate(word):
            if index in at:
                spans.append((pos, pos + len(part), at[index]))
            pos += len(part)
        return spans

    def _ref(self, word, name):
        """A $NAME part about to be added to word."""
        if word is self.word:
            self.refs.append((len(word), name))
        else:
            self.opaque = True

    def _piece(self, i, end, word):
        """One quoted or expanded part of a word at text[i]. Returns (next index, quoted)."""
        text = self.text
        c = text[i]
        if c == "'":
            j = text.find("'", i + 1, end)
            if j == -1:
                self.result.error = True
                word.append(text[i + 1:end])
                return end, True
            word.append(text[i + 1:j])
            return j + 1, True
        if c == '"':
            return self._dquote(i + 1, end, word), True
        if c == "\\":
            word.append(text[i + 1:i + 2])
            return min(i + 2, end), True
        if c == "$":
            return self._dollar(i, end, word, False)
        if c == "`":
            return self._backtick(i, end, word), False
        word.append(c)
        return i + 1, False

    def _dquote(self, i, end, word):
        """Inside "...": only \\, $ and ` are special. Returns the index past the closing quote."""
        text = self.text
        while i < end:
            m = _DQ_PLAIN.match(text, i, end)
            if m:
                word.append(m.group())
                i = m.end()
                continue
            c = text[i]
            if c == '"':
                return i + 1
            if c == "\\":
                nxt = text[i + 1:i + 2]
                if nxt in ("$", "`", '"', "\\"):
                    word.append(nxt)
                elif nxt != "\n":
                    word.append(c + nxt)
                i += 2
            elif c == "$":
                i, _q = self._dollar(i, end, word, True)
            else:
                i = self._backtick(i, end, word)
        self.result.error = True
        return end

    def _dollar(self, i, end, word, dq):
        """An expansion at text[i] == '$'. Returns (next index, quoted)."""
        text = self.text
        nxt = text[i + 1:i + 2] if i + 1 < end else ""
        if nxt == "(":
            self._enter()
            if text.startswith("((", i + 1) and self._is_arith(i + 1):
                self.nest -= 1
                word.append(_ARITH)
                return self._arith(i + 3, end, ")"), False
            word.append(_SUBST)
            j = self._sub(i + 2, end)
            self.dyn = self.opaque = True
            return j, False
        if nxt == "{":
            j = self._braces(i + 2, end, dq)
            inner = text[i + 2:j - 1]
            if inner not in _SAFE_VARS:
                self.dyn = True
                if _IDENT.fullmatch(inner) and text[j - 1:j] == "}":
                    self._ref(word, inner)
                else:
                    self.opaque = True
            word.append(text[i:j])  # Kept as written, so ${HOME}/... still resolves as a path.
            return j, False
        if nxt == "[":
            word.append(_ARITH)
            return self._arith(i + 2, end, "]"), False
        if nxt == "'" and not dq:
            return self._ansi_c(i + 2, end, word), True
        if nxt == '"' and not dq:
            return i + 1, False  # $"..." is a double-quoted string.
        m = _VAR_NAME.match(text, i + 1, end)
        if m and m.group() not in _SAFE_VARS:
            self.dyn = True
            if _IDENT.fullmatch(m.group()):
                self._ref(word, m.group())
                word.append("$" + m.group())
                return m.end(), False
            self.opaque = True
        word.append("$")
        return i + 1, False

    def _sub(self, i, end):
        """A $(...) or <(...) body starting at i; the caller has entered one level."""
        saved = self.word, self.refs, self.opaque, self.dyn
        tokens, j = self.lex(i, end, True)
        self.word, self.refs, self.opaque, self.dyn = saved
        self.nest -= 1
        self.inners.append(tokens)
        return j

    def _backtick(self, i, end, word):
        """`...`: the body, with \\$, \\` and \\\\ unescaped, is read again as its own command line."""
        text = self.text
        parts = []
        j = i + 1
        while j < end:
            m = _BACKTICK_PLAIN.match(text, j, end)
            if m:
                parts.append(m.group())
                j = m.end()
                continue
            if text[j] == "`":
                break
            nxt = text[j + 1:j + 2]
            parts.append(nxt if nxt in ("$", "`", "\\") else "\\" + nxt)
            j += 2
        else:
            self.result.error = True
        word.append(_SUBST)
        inner = _Lexer("".join(parts), self.result, self.depth + self.nest + 1)
        tokens, inners = inner.run()
        self.inners.append(tokens)
        self.inners.extend(inners)
        self.dyn = self.opaque = True
        return min(j + 1, end)

    def _nested(self, i, end, opener, closer, arith, dq=False):
        """Skip a ${...}, $((...)) or $[...] body to its closer, reading the substitutions inside.

        Quotes are honored when finding the end, as the shell does; in arithmetic a lone `)` also ends it.
        Single-quoted text here can still run $(...): bash and zsh evaluate subscripts and offsets
        (${a['$(cmd)']}, (( 'a[$(cmd)]' ))), so substitutions in it are read too.
        """
        self._enter()
        text = self.text
        scratch = []
        depth = 0
        while i < end:
            m = _NEST_PLAIN.match(text, i, end)
            if m:
                i = m.end()
                continue
            c = text[i]
            if c == "\\":
                i += 2
            elif c == "'":
                j = text.find("'", i + 1, end)
                j = end if j == -1 else j
                span = text[i + 1:j]
                if dq and not arith and (j == end or "}" in span or '"' in span):
                    self.result.flag("ask", _QUOTE_REASON)
                self._quoted_substitutions(span)
                i = min(j + 1, end)
            elif c == '"':
                i = self._dquote(i + 1, end, scratch)
            elif c == "$":
                i, _q = self._dollar(i, end, scratch, arith or dq)
            elif c == "`":
                i = self._backtick(i, end, scratch)
            elif c == opener:
                depth += 1
                i += 1
            elif c == closer:
                if depth == 0:
                    self.nest -= 1
                    if arith and closer == ")" and text.startswith(")", i + 1):
                        return i + 2
                    return i + 1
                depth -= 1
                i += 1
            else:
                i += 1
        self.nest -= 1
        return end

    def _braces(self, i, end, dq=False):
        return self._nested(i, end, "{", "}", False, dq)

    def _quoted_substitutions(self, span):
        """Read the $(...) and `...` in quoted text the shell will evaluate; the text itself is not a command."""
        if "$(" in span or "`" in span:
            tokens, inners = _Lexer(span, self.result, self.depth + self.nest + 1).run()
            self.inners.extend(inners)

    def _arith(self, i, end, closer):
        return self._nested(i, end, "(" if closer == ")" else "[", closer, True)

    def _ansi_c(self, i, end, word):
        """$'...' with C escapes, where \\' does not end the string. Returns the index past the closing quote."""
        text = self.text
        while i < end:
            m = _ANSI_PLAIN.match(text, i, end)
            if m:
                word.append(m.group())
                i = m.end()
                continue
            if text[i] == "'":
                return i + 1
            i = self._ansi_escape(i + 1, end, word)
        self.result.error = True
        return end

    def _ansi_escape(self, i, end, word):
        text = self.text
        c = text[i:i + 1] if i < end else ""
        if c and c in _ANSI_ESCAPES:
            word.append(_ANSI_ESCAPES[c])
            return i + 1
        if c in _ANSI_NUMBERS:
            pattern, base = _ANSI_NUMBERS[c]
            m = pattern.match(text, i if c.isdigit() else i + 1, end)
            if m:
                code = int(m.group(), base)
                word.append(chr(code & 0xFF) if base == 8 else chr(code) if code <= 0x10FFFF else "")
                return m.end()
        if c == "c" and i + 1 < end:
            word.append(chr(ord(text[i + 1]) & 0x1F))
            return i + 2
        word.append("\\" + c)
        return min(i + 1, end)

    def _is_arith(self, i):
        """True when the (( at text[i] closes with )) as one pair, as the shell requires for arithmetic.

        The end is found honoring quotes, `...` and ${...}, as bash and zsh do. When the body has quotes or
        expansions, which shells read in slightly different ways, it is also read as commands, so a reading where
        it is a subshell hides nothing.
        """
        found = self._arith_at.get(i)
        if found is None:
            close = self._paren_close(i + 2)
            found = close is not None and self.text.startswith("))", close)
            self._arith_at[i] = found
            body = self.text[i + 2:close] if found else ""
            if any(q in body for q in ("'", '"', "`", "${")):
                tokens, inners = _Lexer(body, self.result, self.depth + self.nest + 1).run()
                self.inners.append(tokens)
                self.inners.extend(inners)
        return found

    def _paren_close(self, j):
        """Index of the ) that closes an open ( just before text[j], or None. Counts toward the work limit."""
        text = self.text
        end = len(text)
        start = j
        stack = [")"]
        while j < end:
            m = _SCAN_PLAIN.match(text, j)
            if m:
                j = m.end()
                continue
            c = text[j]
            top = stack[-1]
            if c == "\\":
                j += 2
                continue
            if top in ('"', "`"):
                if c == top:
                    stack.pop()
                elif top == '"' and c == "$" and text[j + 1:j + 2] in ("(", "{"):
                    stack.append(")" if text[j + 1] == "(" else "}")
                    j += 1
                elif top == '"' and c == "`":
                    stack.append("`")
                j += 1
                continue
            if c == "'":
                k = text.find("'", j + 1)
                j = end if k == -1 else k + 1
                continue
            if c in ('"', "`"):
                stack.append(c)
            elif c == "$" and text[j + 1:j + 2] in ("(", "{"):
                stack.append(")" if text[j + 1] == "(" else "}")
                j += 1
            elif c == "(" and top == ")":
                stack.append(")")
            elif c == "{" and top == "}":
                stack.append("}")
            elif c == top:
                stack.pop()
                if not stack:
                    self._count(j - start)
                    return j
            j += 1
        self._count(j - start)
        return None

    def _count(self, n):
        self.result.work += n
        if self.result.work > MAX_WORK:
            raise _Limit(_WORK_REASON)

    def _delimiter(self, i, end, strip_tabs):
        """Read the heredoc word after << or <<- as the shell does: one whole word, quotes removed, not expanded.

        Returns (index after it, _HereDoc or None).
        """
        text = self.text
        while i < end and text[i] in " \t":
            i += 1
        parts = []
        quoted = False
        while i < end:
            c = text[i]
            if c in _BREAK:
                break
            if c == "'" or c == '"':
                j = text.find(c, i + 1, end)
                j = end if j == -1 else j
                parts.append(text[i + 1:j])
                quoted = True
                i = j + 1
            elif c == "\\":
                parts.append(text[i + 1:i + 2])
                quoted = True
                i += 2
            elif c == "$" and text.startswith("'", i + 1):
                i = self._ansi_c(i + 2, end, parts)
                quoted = True
            elif c == "$" and text[i + 1:i + 2] in ("(", "{", "["):
                j = self._skip_verbatim(i + 1, end)
                parts.append(text[i:j])
                i = j
            elif c == "`":
                j = text.find("`", i + 1, end)
                j = end if j == -1 else j + 1
                parts.append(text[i:j])
                i = j
            else:
                parts.append(c)
                i += 1
        if not parts:
            return min(i, end), None
        return min(i, end), _HereDoc("".join(parts), strip_tabs, not quoted)

    def _skip_verbatim(self, i, end):
        """Index past the bracket group opening at text[i], counting only brackets (a heredoc word is not run)."""
        text = self.text
        opener = text[i]
        closer = {"(": ")", "{": "}", "[": "]"}[opener]
        depth = 0
        while i < end:
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return end

    def _heredoc_bodies(self, pending, i, end, sub):
        """Read each pending heredoc body from i. Returns the index where reading commands resumes.

        Inside $(...), a line that starts with the delimiter followed by `)` also ends the body (bash reads
        `EOF)` that way), and the `)` then closes the substitution. Ending early is the safe side: anything after
        is read as commands.
        """
        text = self.text
        for doc in pending:
            start = i
            resume = body_end = end
            closes = False
            while i < end:
                j = text.find("\n", i, end)
                line_end = end if j == -1 else j
                line = text[i:line_end]
                cmp = line.lstrip("\t") if doc.strip_tabs else line
                if cmp == doc.delim:
                    body_end, resume = i, (line_end + 1 if j != -1 else end)
                    break
                if sub and cmp.startswith(doc.delim) and cmp[len(doc.delim):].lstrip(" \t").startswith(")"):
                    k = i + len(line) - len(cmp) + len(doc.delim)
                    while text[k] in " \t":
                        k += 1
                    body_end, resume, closes = i, k, True
                    break
                i = line_end + 1 if j != -1 else end
            body = text[start:body_end]
            if doc.strip_tabs:
                body = "".join(line.lstrip("\t") for line in body.splitlines(True))
            doc.body = body
            if doc.expands:
                self._body_substitutions(start, body_end)
            i = resume
            if closes:
                return resume
        return i

    def _body_substitutions(self, i, end):
        """$(...) and `...` in an unquoted heredoc body run when the heredoc is read."""
        text = self.text
        scratch = []
        while i < end:
            m = _BODY_PLAIN.match(text, i, end)
            if m:
                i = m.end()
                continue
            c = text[i]
            if c == "\\":
                i += 2
            elif c == "$":
                i, _q = self._dollar(i, end, scratch, True)
            else:
                i = self._backtick(i, end, scratch)


def _is_assignment(tok):
    if "=" not in tok or tok.startswith("="):
        return False
    name = tok.split("=", 1)[0]
    return name.replace("_", "a").isalnum() and not name[0].isdigit()


@functools.lru_cache(maxsize=1024)
def _base(word):
    """A program name as matched: case is ignored, as macOS file systems do (GIT runs git)."""
    return os.path.basename(word).lower()


# Options that move a program's own folder: program -> (short option, long option).
_CHDIR_OPTIONS = {"env": ("-C", "--chdir"), "sudo": ("-D", "--chdir"), "make": ("-C", "--directory"),
                  "gmake": ("-C", "--directory")}


def _chdir_value(name, argv, i):
    """(folder, words used) when argv[i] is name's change-folder option, else None."""
    short, long_name = _CHDIR_OPTIONS.get(name, (None, None))
    a = argv[i]
    if short is None:
        return None
    if a in (short, long_name):
        return (argv[i + 1], 2) if i + 1 < len(argv) else ("", 1)
    if a.startswith(long_name + "="):
        return a[len(long_name) + 1:], 1
    if a.startswith(short) and not a.startswith("--"):
        return a[2:], 1
    return None


def _short_letters(arg, takes):
    """The letters of a short-option cluster up to and including the first one that takes a value."""
    letters = []
    for ch in arg[1:]:
        letters.append(ch)
        if "-" + ch in takes:
            break
    return "".join(letters)


def _option_span(args, i, takes):
    """How many words the option at args[i] uses: 2 when its value is the next word (-u me, -Hu me, --user me),
    else 1 (-ume, --user=me, -H)."""
    a = args[i]
    if a in takes:
        return 2
    if a.startswith("--") or len(a) < 2:
        return 1
    letters = _short_letters(a, takes)
    return 2 if "-" + letters[-1] in takes and len(letters) == len(a) - 1 else 1


_ENV_S_ESCAPES = {"\\": "\\", "'": "'", '"': '"', "$": "$", "#": "#", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
                  "v": "\v"}


def _env_split(value):
    """The words env -S makes of value, or None when they can't be known exactly.

    Outside quotes blanks and \\_ separate words and \\c ends the string; '...' keeps text except \\\\ and \\';
    "..." reads escapes, with \\_ as a blank. ${VAR}, an unknown escape or an unclosed quote give None.
    """
    words = []
    word = []
    in_word = False
    quote = None
    i = 0
    while i < len(value):
        c = value[i]
        if quote == "'":
            if c == "'":
                quote = None
            elif c == "\\" and value[i + 1:i + 2] in ("\\", "'"):
                word.append(value[i + 1])
                i += 1
            else:
                word.append(c)
            i += 1
            continue
        if c == "$":
            return None  # env expands ${VAR} itself, to text checkrein can't see.
        if c == "\\":
            nxt = value[i + 1:i + 2]
            if nxt == "_":
                if quote:
                    word.append(" ")
                elif in_word:
                    words.append("".join(word))
                    word, in_word = [], False
            elif nxt == "c" and not quote:
                break
            elif nxt in _ENV_S_ESCAPES:
                word.append(_ENV_S_ESCAPES[nxt])
                in_word = True
            else:
                return None
            i += 2
            continue
        if quote == '"':
            if c == '"':
                quote = None
            else:
                word.append(c)
            i += 1
            continue
        if c in " \t\n\r\f\v":
            if in_word:
                words.append("".join(word))
                word, in_word = [], False
        elif c == "#" and not in_word:
            break
        elif c in ("'", '"'):
            quote, in_word = c, True
        else:
            word.append(c)
            in_word = True
        i += 1
    if quote:
        return None
    if in_word:
        words.append("".join(word))
    return words


def _env_split_option(arg):
    """For an env option word with -S / --split-string: (option letters before S, value or None when it is the
    next word). None when the word does not split (-uSHELL is -u SHELL)."""
    if arg == "--split-string":
        return "", None
    if arg.startswith("--split-string="):
        return "", arg[len("--split-string="):]
    if not arg.startswith("-") or arg.startswith("--"):
        return None
    for k, ch in enumerate(arg[1:], 1):
        if ch in "uC":
            return None
        if ch == "S":
            return arg[1:k], (arg[k + 1:] or None)
    return None


def _xargs_replace(arg, takes):
    """The replace string an xargs option sets (-I {}, -i, --replace, BSD -J), "" when it is the next word, or None."""
    if arg == "--replace":
        return "{}"
    if arg.startswith("--replace="):
        return arg[len("--replace="):]
    if not arg.startswith("-") or arg.startswith("--"):
        return None
    letters = _short_letters(arg, takes)
    rest = arg[1 + len(letters):]
    if letters[-1] in "IJ":
        return rest
    if "i" in letters:
        return arg[arg.index("i", 1) + 1:] or "{}"
    return None


def _unwrap(argv, env, dirs=None, result=None, xargs=None):
    """Remove wrapper commands and their options. Returns (argv, env).

    Folders a wrapper moves the command to (env -C, a privilege wrapper's -D) are added to dirs. Problems (an env -S string that
    can't be split exactly, wrappers nested past the limit) are flagged on result when given. When xargs is a
    list, each xargs passed through adds (replace string or None, whether its items are split on plain blanks),
    and its replace string becomes _XITEM in argv instead of _SUBST, for the caller to fill in.
    """
    argv = list(argv)
    start = 0
    rounds = 0
    while start < len(argv):
        name = _base(argv[start])
        if name not in WRAPPERS:
            break
        rounds += 1
        if rounds > MAX_WRAPPERS:
            if result is not None:
                result.flag("ask", _WRAPPERS_REASON)
            break
        if result is not None:
            result.step()
        takes = WRAPPERS[name]
        i = start + 1
        if name == "command" and argv[i:i + 1] and argv[i] in ("-v", "-V"):
            return [], env  # a lookup, not a run
        if name == "xcrun" and {"-f", "--find"} & set(argv[i:]):
            return [], env
        shell = False  # A privilege wrapper's -s / -i: with no command, a shell that reads its script from stdin.
        replace = None
        plain = True  # xargs splits its input on blanks and newlines (no -0, -d, -E, -a).
        while i < len(argv):
            a = argv[i]
            chdir = _chdir_value(name, argv, i)
            if chdir is not None:
                if dirs is not None:
                    dirs.append(chdir[0])
                i += chdir[1]
                continue
            if name == "env" and _is_assignment(a):
                k, v = a.split("=", 1)
                env[k] = _Dyn(v) if isinstance(a, _Dyn) else v
                i += 1
                continue
            if a == "--":
                i += 1
                break
            split = _env_split_option(a) if name == "env" else None
            if split is not None:
                # env -S splits its value into words and runs them: the value is the command.
                before, value = split
                used = 1
                if value is None:
                    value = argv[i + 1] if i + 1 < len(argv) else ""
                    used = 2
                words = None if isinstance(value, _Dyn) else _env_split(value)
                if words is None:
                    if result is not None:
                        result.flag("ask", _UNKNOWN % (_UNKNOWN_SPLIT % value))
                    words = value.split()
                argv[i:i + used] = (["-" + before] if before else []) + words
                continue
            if a.startswith("-") and len(a) > 1:
                if name in ("sudo", "doas") and (a in ("--shell", "--login") or (
                        not a.startswith("--") and set(_short_letters(a, takes)) & set("si"))):
                    shell = True
                if name == "xargs":
                    found = _xargs_replace(a, takes)
                    if found is not None:
                        replace = found or (argv[i + 1] if i + 1 < len(argv) else None)
                    if a.startswith(("--null", "--delimiter", "--eof", "--arg-file")) or (
                            not a.startswith("--") and set(_short_letters(a, takes)) & set("0dEea")):
                        plain = False
                i += _option_span(argv, i, takes)
                continue
            if name in ("timeout", "gtimeout") and a[:1].isdigit():
                i += 1
                continue
            if name == "nice" and a.lstrip("-").isdigit():
                i += 1
                continue
            break
        if shell and i >= len(argv):
            return ["sh"], env
        start = i
        if name == "xargs" and xargs is not None:
            xargs.append((replace, plain))
        if replace:
            # Each input line takes the place of the replace string, as unknown as a substitution's output.
            item = _SUBST if xargs is None else _XITEM
            argv[start:] = [(_Dyn if isinstance(a, _Dyn) else str)(a.replace(replace, item)) if replace in a else a
                           for a in argv[start:]]
    return argv[start:], env
def _expand_path(word, cwd, home):
    """Expand ~ and $HOME-style references and make a path absolute."""
    w = word
    if w.startswith("~/") or w == "~":
        w = home + w[1:]
    for var in ("$HOME", "${HOME}"):
        if w.startswith(var):
            w = home + w[len(var):]
    if "$" not in w:
        if cwd and _plain_relative(w) and _plain_folder(cwd):
            # Folders checkrein tracks are already normal; normpath on long ones is slow on Python 3.9.
            return cwd + "/" + w.rstrip("/")
        return os.path.normpath(w if os.path.isabs(w) else os.path.join(cwd or os.getcwd(), w))
    for var, val in (("$CLAUDE_PLUGIN_DATA", os.environ.get("CLAUDE_PLUGIN_DATA")),
                     ("${CLAUDE_PLUGIN_DATA}", os.environ.get("CLAUDE_PLUGIN_DATA")),
                     ("$CLAUDE_PLUGIN_ROOT", os.environ.get("CLAUDE_PLUGIN_ROOT")),
                     ("${CLAUDE_PLUGIN_ROOT}", os.environ.get("CLAUDE_PLUGIN_ROOT")),
                     ("$CLAUDE_PROJECT_DIR", os.environ.get("CLAUDE_PROJECT_DIR")),
                     ("${CLAUDE_PROJECT_DIR}", os.environ.get("CLAUDE_PROJECT_DIR"))):
        if val and w.startswith(var):
            w = val + w[len(var):]
    if not os.path.isabs(w):
        w = os.path.join(cwd or os.getcwd(), w)
    return os.path.normpath(w)


def _plain_relative(word):
    """A relative path with no ., .. or empty parts (a trailing / is fine)."""
    parts = word.rstrip("/").split("/")
    return bool(word) and not word.startswith("/") and all(p and p != "." and p != ".." for p in parts)


@functools.lru_cache(maxsize=4096)
def _plain_folder(path):
    """An absolute path normpath would leave as it is, other than /."""
    return path.startswith("/") and not path.endswith("/") and "//" not in path and "/." not in path


def expand_path(word, cwd, home=None):
    return _expand_path(word, cwd, home or os.path.expanduser("~"))


def parse(command, cwd=None, home=None, _depth=0, _result=None):
    """Parse a command line into a ParseResult with a flat list of Cmd.

    A command too large or too deeply nested to read sets result.problem (with problem_level ask or deny) instead.
    """
    home = home or os.path.expanduser("~")
    where = ((cwd,), False)
    if _result is not None:
        _parse(command, where, home, _depth, _result)
        return _result
    result = ParseResult()
    if len(command or "") > MAX_COMMAND:
        result.flag("ask", "The command is %d KB, more than the %d KB checkrein reads, so it was not checked."
                    % (len(command) // 1024, MAX_COMMAND // 1024))
        return result
    result.text = command or ""
    try:
        _parse(command, where, home, _depth, result)
    except _Limit as exc:
        result.flag("deny", str(exc))
    except RecursionError:
        result.flag("deny", _DEPTH_REASON)
    if result.error:
        result.flag("ask", _OPEN_QUOTE_REASON)
    return result


def _parse(command, where, home, depth, result, scope=None):
    """Read command into result.cmds. where is (folders, unknown) at its start; returns the same for every folder
    its commands may run in. scope holds the shell's variables; text read in the same shell (eval, source) shares
    it, so its assignments carry on."""
    if not command:
        return where
    scope = scope if scope is not None else _Scope()
    tokens, inners = _Lexer(command, result, depth).run()
    start = len(result.cmds)
    walker = _Walker(where, home, depth, result, scope)
    seen = walker.walk(tokens)
    outer = result.cmds[start:]
    del result.cmds[start:]
    # A substitution runs where its command runs, so every folder the line reaches is possible. Nested ones come
    # first in inners: reading from the end carries the folders an outer substitution's cd adds into inner ones.
    pieces = []
    for inner in reversed(inners):
        mark = len(result.cmds)
        seen = _merge(seen, _Walker(seen, home, depth + 1, result, scope.copy()).walk(inner))
        pieces.append(result.cmds[mark:])
        del result.cmds[mark:]
    for piece in reversed(pieces):
        result.cmds.extend(piece)
    result.cmds.extend(outer)
    return seen


def _union(*groups):
    """The folders of all groups, in order, each once."""
    return tuple(dict.fromkeys(d for group in groups for d in group))


def _merge(a, b):
    dirs = _union(a[0], b[0])
    if len(dirs) > MAX_DIRS:
        return dirs[:MAX_DIRS], True
    return dirs, a[1] or b[1]


class _Scope(object):
    """The variables of one shell.

    values maps each name assigned in the command line to its value (a _Dyn when built at run time). Every one
    of them reaches the environment of later commands: checkrein can't know which names were exported before.
    Only names in known resolve $NAME: assigned a literal value for sure, and written nowhere else (a loop, read,
    unset or ${NAME:=...} could change them). counts is how often each name was assigned or exported here, to
    compare with how often the line writes it.
    """

    __slots__ = ("values", "known", "exported", "allexport", "counts", "inherited")

    def __init__(self):
        self.values = {}
        self.known = set()
        self.exported = set()
        self.allexport = False
        self.counts = {}
        self.inherited = {}  # The environment a child shell got from its parent.

    def copy(self):
        new = _Scope()
        new.values, new.known, new.exported = dict(self.values), set(self.known), set(self.exported)
        new.allexport, new.counts, new.inherited = self.allexport, dict(self.counts), dict(self.inherited)
        return new

    def env(self, prefix):
        """The environment a command with these prefix assignments runs with."""
        out = dict(self.inherited)
        out.update(self.values)
        out.update(prefix)
        return out

    def child(self, prefix):
        """The scope of a child shell (sh -c, bash script) started with these prefix assignments."""
        new = _Scope()
        new.inherited = self.env(prefix)
        passed = [k for k in self.values if k in self.exported]
        new.values = {k: self.values[k] for k in passed}
        new.values.update(prefix)
        new.known = {k for k in passed if k in self.known}
        new.known.update(k for k, v in prefix.items() if not isinstance(v, _Dyn))
        new.exported = set(new.values)
        new.counts = {k: self.counts.get(k, 0) + (k in prefix) for k in new.values}
        return new

    def assign(self, name, value, sure, export=False):
        self.counts[name] = self.counts.get(name, 0) + 1
        self.values[name] = value
        if sure and not isinstance(value, _Dyn):
            self.known.add(name)
        else:
            self.known.discard(name)
        if export or self.allexport:
            self.exported.add(name)


_CD = {"cd", "chdir", "pushd", "popd"}
# Builtins that evaluate their words as arithmetic or array subscripts, where $(...) runs even from quoted text.
_EVALUATES = {"let", "declare", "typeset", "local", "export", "readonly", "integer", "float", "read", "[[", "mapfile",
              "readarray", "getopts"}
_SUBSCRIPT_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\[.*\]\+?=", re.S)
# Words after which an assignment may not run, or may run more than once.
_COMPOUND = {"if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do", "done",
             "function", "{", "}", "coproc"}
# Builtins whose NAME=value words assign shell variables: name -> whether they export.
_DECLARES = {"export": True, "declare": False, "typeset": False, "local": False, "readonly": False}
# Variables the shell evaluates as prompts (their $(...) runs) or as commands.
_PROMPT_VARS = {"PS0", "PS1", "PS2", "PS3", "PS4", "PROMPT", "RPROMPT", "RPS1", "RPS2", "PROMPT2", "PROMPT3",
                "PROMPT4", "SPROMPT"}
_COMMAND_VARS = {"PROMPT_COMMAND"}


class _Walker(object):
    """Turns one token list into Cmds, tracking the folders each command may run in and the shell's variables.

    cur holds the folders the next command may run in. A cd moves cur only for the commands joined to it by &&;
    after any other separator the folder before it is possible again (the cd may have failed), a subshell's cd ends
    with the subshell, and a cd in a pipeline may run in a subshell (bash) or not (zsh's last stage), so both count.
    """

    def __init__(self, where, home, depth, result, scope):
        self.cur, self.unknown = where
        self.maybe = ()  # Folders possible again once the current && chain ends.
        self.frames = []  # State saved at each ( subshell.
        self.stack = []  # The pushd stack.
        self.seen = self.cur
        self.home = home
        self.depth = depth
        self.result = result
        self.scope = scope
        self.prev_out = None
        self.prev_found = None  # (roots, predicates) when the stage before a pipe is find or ls.
        self.found = ((), ())  # found_roots and found_predicates for the commands added now.
        self.sep = ";"  # The separator before the current command.
        self.compound = False  # A compound command or group started: later assignments may not run.

    def where(self):
        return self.cur, self.unknown

    def union(self, *groups):
        """The folders of groups, each once. Past MAX_DIRS of them, or a path past MAX_PATH, the folder is
        unknown and only the first ones are kept."""
        dirs = _union(*groups)
        self.result.step(len(dirs))
        short = tuple(d for d in dirs if d is None or len(d) <= MAX_PATH)
        if len(short) < len(dirs) or len(short) > MAX_DIRS:
            self.unknown = True
            return short[:MAX_DIRS] or dirs[:1]
        return dirs

    def walk(self, tokens):
        current = []
        piped = False
        loose = "case" in tokens  # A case pattern's ) closes no subshell, so ) can't be trusted to restore.
        for tok in list(tokens) + [_Op(";")]:
            if isinstance(tok, _Op) and tok in SEPARATORS:
                if current:
                    self.group(current, piped)
                    piped = tok in _PIPES
                elif tok not in (";", "(", "{"):
                    piped = tok in _PIPES  # A newline or group opener after | still continues the pipeline.
                current = []
                self.separator(tok, loose)
            else:
                current.append(tok)
        return self.seen, self.unknown

    def separator(self, tok, loose):
        self.result.step()
        if tok in ("{", "}"):
            self.compound = True
        if tok not in ("(", ")", "{", "}"):
            self.sep = tok
        if tok == "(":
            self.frames.append((self.cur, self.maybe, list(self.stack), self.scope.copy()))
            self.maybe = ()
        elif tok == ")":
            if self.frames:
                cur, maybe, stack, scope = self.frames.pop()
                self.cur = self.union(cur, self.cur, self.maybe) if loose else cur
                self.maybe, self.stack = maybe, stack
                if loose:
                    scope.known.intersection_update(self.scope.known)
                self.scope.values, self.scope.known = scope.values, scope.known
                self.scope.exported, self.scope.allexport = scope.exported, scope.allexport
        elif tok not in ("&&", "{", "}"):
            self.cur, self.maybe = self.union(self.cur, self.maybe), ()

    def resolve(self, tok, pending=()):
        """tok with each $NAME replaced by its literal value, when every one is known; else tok unchanged.

        A value with blanks or glob characters would be split or matched by the shell, so it stays unknown, and
        so does a name assigned in the same command (pending).
        """
        refs = tok.refs if isinstance(tok, _Dyn) else None
        if not refs:
            return tok
        scope = self.scope
        out = []
        last = 0
        for start, end, name in refs:
            value = scope.values.get(name)
            if (name not in scope.known or name in pending or value is None
                    or self.result.name_uses(name) > scope.counts.get(name, 0)
                    or any(ch in value for ch in " \t\n*?[")):
                return tok
            out.append(tok[last:start])
            out.append(value)
            last = end
        out.append(tok[last:])
        return "".join(out)

    def group(self, group, piped):
        self.result.step(len(group) + 1)
        env = {}
        redirects = []
        stdin = []
        stdin_unknown = False
        argv = []
        i = 0
        if group[0] in _COMPOUND or (len(group) > 1 and group[1] == "()"):
            self.compound = True
        while i < len(group):
            tok = group[i]
            if isinstance(tok, _Op):
                has_target = i + 1 < len(group) and not isinstance(group[i + 1], _Op)
                target = self.resolve(group[i + 1]) if has_target else ""
                redirects.append((str(tok), str(target)))
                if isinstance(target, _HereDoc):
                    stdin.append(target.body)
                elif tok == "<<<":
                    stdin.append(target + "\n")
                elif tok == "<" and isinstance(target, _ProcSub):
                    text = _procsub_output(target)
                    stdin_unknown = stdin_unknown or text is None
                    stdin.append(text or "")
                i += 2 if has_target else 1
                continue
            if not argv and not env and tok in RESERVED:
                i += 1
                continue
            if not argv and not env and tok == "repeat" and i + 1 < len(group):
                i += 2  # zsh: repeat N cmd.
                continue
            if not argv and (_is_assignment(tok) or _SUBSCRIPT_ASSIGNMENT.match(tok)):
                word = self.resolve(tok, env)
                k, v = word.split("=", 1)
                env[k] = _Dyn(v) if isinstance(word, _Dyn) or k.endswith(("+", "]")) else v
                # a['$(cmd)']=1 runs cmd, and so does x='a[$(cmd)]' once x is used in arithmetic.
                if "[" in tok:
                    self.quoted_substitutions(tok)
                i += 1
                continue
            argv.append(self.resolve(tok))
            i += 1
        # A trailing fd number before a redirect (2>file) stays as an argument; drop pure digits.
        argv = [a for a in argv if not (a.isdigit() and len(a) == 1 and redirects)] if redirects else argv
        dirs = []
        xargs = []
        argv, env = _unwrap(argv, env, dirs, self.result, xargs)
        stdin_text = "".join(stdin)
        piped_text = self.prev_out if piped else _NO_PIPE
        piped_found = self.prev_found if piped else None
        self.prev_out = _stage_output(argv, stdin_text, piped_text)
        self.prev_found = _stage_found(argv)
        for k, v in env.items():
            self.prompt_value(k, v)
        if not argv:
            self.assign_all(env, piped)
            if redirects:
                self.add(Cmd([":"], env, redirects, self.cur[0], self.depth, stdin_text))
            return
        if xargs and argv:
            runs, found = _xargs_runs(xargs, argv, stdin_text or piped_text, piped_found)
            saved = self.found
            self.found = found or saved
            for run in runs:
                self.run_in(dirs, lambda: self.run(run, env, redirects, stdin_text, piped_text, stdin_unknown, piped))
            self.found = saved
            return
        self.run_in(dirs, lambda: self.run(argv, env, redirects, stdin_text, piped_text, stdin_unknown, piped))

    def sure(self, piped):
        """Whether an assignment here surely runs, once, in this shell."""
        return not (self.compound or piped or self.sep in ("&&", "||", "|", "|&", "&"))

    def assign_all(self, assignments, piped, export=False):
        sure = self.sure(piped)
        for k, v in assignments.items():
            name = k.rstrip("+")
            if "[" in name or not _IDENT.fullmatch(name):
                continue
            self.scope.assign(name, v, sure and not k.endswith("+"), export)

    def prompt_value(self, name, value):
        """A prompt variable's $(...) runs each time the prompt is shown (PS4 with -x, ${x@P}); PROMPT_COMMAND runs
        as a command."""
        if name in _COMMAND_VARS:
            self.parse(value, isinstance(value, _Dyn), name, same=True)
        elif name in _PROMPT_VARS or self.result.prompt_expansion():
            self.quoted_substitutions(value)

    def declares(self, name, argv, piped):
        """export / declare / typeset / local / readonly NAME=value and NAME; set -a."""
        if name in ("set", "setopt"):
            prev = ""
            for a in argv[1:]:
                if name == "set" and a[:1] in ("-", "+") and not a.startswith("--") and "a" in a[1:]:
                    self.scope.allexport = a[0] == "-"
                elif a.lower().replace("_", "") in ("allexport", "noallexport"):
                    on = not a.lower().startswith("no")
                    self.scope.allexport = not on if prev == "+o" else on
                prev = a
            return
        if name == "unset":
            for a in argv[1:]:
                self.scope.values.pop(a, None)
                self.scope.known.discard(a)
            return
        export = _DECLARES[name]
        options = ""
        assignments = {}
        for a in argv[1:]:
            if a.startswith(("-", "+")) and not _is_assignment(a):
                options += a[1:] if a[0] == "-" else ""
                continue
            if "=" in a and _IDENT.fullmatch(a.split("=", 1)[0].split("[", 1)[0].rstrip("+")):
                k, v = a.split("=", 1)
                odd = set(options) & set("aAinlu") or k.endswith("+") or "[" in k
                assignments[k] = _Dyn(v) if isinstance(a, _Dyn) or odd else v
            elif _IDENT.fullmatch(a) and (export or "x" in options):
                self.scope.counts[a] = self.scope.counts.get(a, 0) + 1
                self.scope.exported.add(a)
        if "n" in options and export:
            return
        for k, v in assignments.items():
            self.prompt_value(k, v)
        self.assign_all(assignments, piped, export or "x" in options)

    def run_in(self, dirs, call):
        """Call with the folder moved to dirs (env -C, a privilege wrapper's -D, make -C): only that one command runs there."""
        if not dirs:
            return call()
        saved = self.cur, self.unknown, self.maybe, list(self.stack)
        if len(dirs) > MAX_DIRS:
            # Past the limit (git -C d0 -C d1 ... repeated), the folder is unknown; reading each move costs time.
            dirs = list(dirs[:MAX_DIRS]) + [_SUBST]
        for d in dirs:
            if _unknown_dir(d):
                self.unknown = True
            elif d:
                self.cur = self.union(*[(_expand_path(d, c, self.home),) for c in self.cur])
        self.seen = self.union(self.seen, self.cur)
        found = call()
        self.cur, self.unknown, self.maybe, self.stack = saved
        return found

    def add(self, cmd):
        cmd.cwd, cmd.cwds, cmd.cwd_unknown = self.cur[0], self.cur, self.unknown
        cmd.inherited_env = self.scope.env({})
        if self.found[0] and not cmd.found_roots:
            cmd.found_roots, cmd.found_predicates = self.found
        self.result.step(len(cmd.inherited_env) + 1)
        self.result.cmds.append(cmd)

    def parse(self, text, dynamic=False, what="", env=None, same=False):
        """Read shell text a command runs: in a child shell started with the prefix assignments env, or in this
        shell (same: eval, source, trap, PROMPT_COMMAND), where its assignments carry on."""
        if dynamic:
            self.result.flag("ask", _UNKNOWN % (_UNKNOWN_BUILT % what))
        scope = self.scope if same else self.scope.child(env or {})
        return _parse(text, self.where(), self.home, self.depth + 1, self.result, scope)

    def absorb(self, where):
        """Text read in this shell (eval, source) can cd too."""
        self.cur, self.unknown = self.union(self.cur, where[0]), self.unknown or where[1]
        self.seen = self.union(self.seen, self.cur)

    def quoted_substitutions(self, text):
        if "$(" in text or "`" in text:
            _tokens, inners = _Lexer(text, self.result, self.depth + 1).run()
            for inner in inners:
                _Walker(self.where(), self.home, self.depth + 2, self.result, self.scope.copy()).walk(inner)

    def run(self, argv, env, redirects, stdin_text="", piped_text=_NO_PIPE, stdin_unknown=False, piped=False,
            aliases=0):
        self.result.step()
        name = _base(argv[0])
        if os.path.basename(argv[0]) in _CD:  # Exact case: /usr/bin/cd (CD on macOS) runs apart and moves nothing.
            self.change_dir(name, argv[1:], piped)
            return
        if isinstance(argv[0], _Dyn) and "/" not in argv[0]:
            self.result.flag("ask", _UNKNOWN % (_UNKNOWN_PROGRAM % argv[0]))
        if name in _EVALUATES or (name in ("printf", "print") and "-v" in argv):
            for a in argv[1:]:
                self.quoted_substitutions(a)
        if name in _DECLARES or name in ("set", "setopt", "unset"):
            self.declares(name, argv, piped)
        if name in SHELLS:
            script = _shell_c_arg(argv)
            if script is not None:
                self.parse(script, isinstance(script, _Dyn), name + " -c", env)
                return
            operand = _script_operand(argv)
            if operand is not None and isinstance(argv[operand], _ProcSub):
                self.procsub_script(name, argv[operand], env)
            self.stdin_script(name, argv, stdin_text, piped_text, stdin_unknown, env)
        if name in ("source", ".") and len(argv) > 1:
            if argv[1] in STDIN_PATHS:
                self.absorb(self.stdin_script(name, None, stdin_text, piped_text, stdin_unknown, same=True))
            elif isinstance(argv[1], _ProcSub):
                self.absorb(self.procsub_script(name, argv[1], same=True))
        if name == "eval":
            self.absorb(self.parse(" ".join(argv[1:]), any(isinstance(a, _Dyn) for a in argv[1:]), "eval",
                                   same=True))
            return
        if name == "git":
            expanded = self.git(argv, env, aliases)
            if expanded is not None:
                self.run(expanded, env, redirects, stdin_text, piped_text, stdin_unknown, piped, aliases + 1)
                return
        if name == "crontab":
            self.crontab(argv, stdin_text, piped_text, stdin_unknown, env)
        if name in ("make", "gmake"):
            self.makefile(argv, stdin_text, piped_text, stdin_unknown, env)
        children = _children(name, argv)
        if children:
            texts, runs, reads = children
            for text, dynamic in texts:
                if text is None:
                    self.result.flag("ask", _UNKNOWN % (_UNKNOWN_FILE % name))
                else:
                    self.parse(text, dynamic, name, env, same=name == "trap")
            saved = self.found
            if name in ("find", "gfind") and runs:
                self.found = _find_found(argv)
            for child in runs:
                self.run_child(child, env)
            self.found = saved
            if reads:
                self.stdin_script(name, None, stdin_text, piped_text, stdin_unknown, env)
        runner = _runner(name, argv)
        if runner:
            for child in runner[1]:
                self.run_in(runner[0], lambda: self.run_child(child, env))
        # make -C moves make itself, so its file arguments resolve there; the recipes it runs are not read.
        dirs = [] if name not in _CHDIR_OPTIONS or name in WRAPPERS else [
            found[0] for found in (_chdir_value(name, argv, i) for i in range(1, len(argv))) if found]
        self.run_in(dirs, lambda: self.add(Cmd(argv, env, redirects, self.cur[0], self.depth, stdin_text)))

    def run_child(self, child, env):
        """Run an argv a command starts (find -exec, xargs, launchers), with the environment it passes on."""
        dirs = []
        child_env = dict(env)
        child, child_env = _unwrap(list(child), child_env, dirs, self.result)
        if child and os.path.basename(child[0]) not in _CD:
            self.run_in(dirs, lambda: self.run(child, child_env, []))

    def git(self, argv, env, aliases):
        """Shell text and commands git runs for its config, environment and subcommands. Returns the argv an alias
        defined in the same call expands to, or None."""
        configs, cdirs, at = _git_globals(argv)
        full_env = self.scope.env(env)
        configs.extend(_git_env_configs(full_env))
        texts = []
        sub = _base(argv[at]) if at < len(argv) else ""
        rest = argv[at + 1:]
        for key, value in configs:
            if key == "alias." + sub.lower() and value is not None and not value.startswith("!") and aliases < 5:
                words = None if isinstance(value, _Dyn) else _split_words(value)
                if words is None:
                    self.result.flag("ask", _UNKNOWN % (_UNKNOWN_BUILT % ("git alias " + sub)))
                    return None
                return argv[:at] + words + rest
        for key, value in configs:
            if key == "alias." + sub.lower() and value is not None:
                if isinstance(value, _Dyn):
                    texts.append((value, True))
                elif value.startswith("!"):
                    texts.append(_text([value[1:]] + rest))
            elif _git_runs_value(key, value):
                text = value[1:] if value and value.startswith("!") else value
                texts.append((text or "", value is None or isinstance(value, _Dyn)))
        for var in _GIT_SHELL_ENV:
            if var in full_env and full_env[var]:
                texts.append((full_env[var], isinstance(full_env[var], _Dyn)))
        texts.extend(_git_sub_texts(sub, rest))

        def read():
            for text, dynamic in texts:
                # The text inherits the variable that holds it; a git it runs would read it again, adding nothing.
                if text in self.result.git_reading:
                    continue
                self.result.git_reading.add(text)
                self.parse(text, dynamic, "git", env)
                self.result.git_reading.discard(text)
            if sub == "bisect" and rest[:1] == ["run"] and len(rest) > 1:
                self.run_child(rest[1:], env)
            if sub == "submodule" and "foreach" in rest:
                words = rest[rest.index("foreach") + 1:]
                while words and words[0] in ("--recursive", "--quiet", "-q"):
                    words = words[1:]
                if words:
                    # Runs in each submodule's folder.
                    self.run_in(["$sm_path"], lambda: self.parse(*_text(words), what="git submodule foreach",
                                                                   env=env))
        self.run_in(cdirs, read)
        return None

    def crontab(self, argv, stdin_text, piped_text, stdin_unknown, env):
        """A crontab file, given by name or on standard input, installs the commands of each line."""
        args = argv[1:]
        if any(a in ("-l", "-r", "-e", "-T", "-V") or (a.startswith("-") and set(a[1:]) & set("lreTV"))
               for a in args if a != "-"):
            return
        i = 0
        while i < len(args) and args[i].startswith("-") and args[i] != "-":
            i += _option_span(args, i, {"-u"})
        if i < len(args) and args[i] != "-":
            self.result.flag("ask", _UNKNOWN % (_UNKNOWN_FILE % "crontab"))
            return
        text = stdin_text or (piped_text if piped_text is not _NO_PIPE else "")
        if not stdin_text and (stdin_unknown or piped_text is None):
            self.result.flag("ask", _UNKNOWN % (_UNKNOWN_PIPE % "crontab"))
            return
        self.parse(_cron_commands(text), False, "crontab", env)

    def makefile(self, argv, stdin_text, piped_text, stdin_unknown, env):
        """make -f - (or /dev/stdin) reads the makefile from stdin: its recipe lines are shell commands."""
        files = []
        args = argv[1:]
        for i, a in enumerate(args):
            if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
                files.append(args[i + 1])
            elif a.startswith(("--file=", "--makefile=")):
                files.append(a.split("=", 1)[1])
            elif a.startswith("-f") and len(a) > 2:
                files.append(a[2:])
        if not any(f in STDIN_PATHS for f in files):
            return
        text = stdin_text or (piped_text if piped_text not in (_NO_PIPE, None) else "")
        if not stdin_text and (stdin_unknown or piped_text is None):
            self.result.flag("ask", _UNKNOWN % (_UNKNOWN_PIPE % "make"))
            return
        recipes = [line[1:].lstrip("@-+ ") for line in text.splitlines() if line.startswith("\t")]
        self.parse("\n".join(recipes), False, "make", env)

    def stdin_script(self, name, argv, stdin_text, piped_text, stdin_unknown, env=None, same=False):
        """A shell with no script operand runs what it reads on stdin."""
        where = self.parse(stdin_text, env=env, same=same)
        if not stdin_text and (argv is None or _reads_stdin(argv)):
            if stdin_unknown or piped_text is None:
                self.result.flag("ask", _UNKNOWN % (_UNKNOWN_PIPE % name))
            elif piped_text is not _NO_PIPE:
                where = _merge(where, self.parse(piped_text, env=env, same=same))
        return where

    def procsub_script(self, name, procsub, env=None, same=False):
        text = _procsub_output(procsub)
        if text is None:
            self.result.flag("ask", _UNKNOWN % (_UNKNOWN_PROCSUB % name))
            return self.where()
        return self.parse(text, env=env, same=same)

    def change_dir(self, name, args, piped):
        old = self.cur
        new = old
        known = True
        if name == "popd":
            if args and args[0][:1] in ("+", "-"):
                return  # Drops a stack entry without moving.
            known = bool(self.stack)
            new = self.stack.pop() if self.stack else old
        else:
            while args and args[0].startswith("-") and len(args[0]) > 1 and name != "pushd":
                if args.pop(0) == "--":
                    break
            if name == "pushd" and args and args[0][:1] in ("+", "-"):
                known = False  # Rotates the stack.
            elif not args:
                if name == "pushd":
                    known = bool(self.stack)
                    new = self.stack.pop() if self.stack else old
                else:
                    new = (self.home,)
            elif args[0] == "":
                new = old
            elif len(args) > 1 or args[0] == "-" or _unknown_dir(args[0]):
                known = False
            else:
                new = self.union(*[(_expand_path(args[0], c, self.home),) for c in old])
                known = all(len(d) <= MAX_PATH for d in new)
            if name == "pushd":
                if len(self.stack) >= MAX_DIRS:
                    self.unknown = True
                    del self.stack[0]
                self.stack.append(old)
        if not known:
            # Somewhere checkrein can't know: keep every folder seen so far (cd - goes back to one of them).
            self.unknown = True
            new = self.seen
        self.maybe = self.union(self.maybe, old)
        self.cur = self.union(new, old) if piped else new
        self.seen = self.union(self.seen, self.cur)


def _unknown_dir(word):
    if len(word) > MAX_PATH:
        return True
    if _SUBST in word or _ARITH in word or "`" in word or any(ch in word for ch in "*?["):
        return True
    if word.startswith("~") and not (word == "~" or word.startswith("~/")):
        return True
    return "$" in _expand_path(word, "/", "/")


def _procsub_output(procsub):
    """What a <(...) prints, when it is one command printing literal text; else None."""
    tokens = list(procsub.tokens)
    while tokens and tokens[-1] == ";" and isinstance(tokens[-1], _Op):
        tokens.pop()
    if not tokens or any(isinstance(t, _Op) for t in tokens):
        return None
    argv, _env = _unwrap(tokens, {})
    return _stage_output(argv, "", _NO_PIPE)


def _script_operand(argv):
    """Index of a shell's script file operand, or None."""
    i = 1
    if _base(argv[0]) == "busybox" and len(argv) > 1 and _base(argv[1]) in SHELLS:
        i = 2
    while i < len(argv):
        a = argv[i]
        if a == "--":
            return i + 1 if i + 1 < len(argv) else None
        if a in _SHELL_VALUE_OPTIONS:
            i += 2
            continue
        if a.startswith(("-", "+")):
            i += 1
            continue
        return i
    return None


_SSH_VALUE = {"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R",
              "-S", "-W", "-w", "-B", "-P"}
_FLOCK_VALUE = {"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"}
_SCRIPT_VALUE = {"-t", "-T", "-I", "-O", "-B", "-E", "-m", "-o", "--log-in", "--log-out", "--log-io",
                 "--log-timing", "--echo", "--logging-format", "--output-limit"}
_PARALLEL_VALUE = {"-j", "-P", "-S", "-n", "-N", "-L", "-l", "-I", "-E", "-d", "-a", "-C", "--jobs", "--sshlogin",
                   "--arg-file", "--delimiter", "--colsep", "--results", "--joblog", "--timeout", "--retries",
                   "--tag-string", "--workdir", "--wd", "--env", "--halt", "--max-args", "--max-replace-args"}
_PARALLEL_SOURCES = {":::", "::::", ":::+", "::::+"}


def _text(words):
    return " ".join(words), any(isinstance(w, _Dyn) for w in words)


def _option_value(args, short, long_names):
    """The value of a -c style option (-c v, -xc v, -cv, --command v, --command=v), or None."""
    for j, a in enumerate(args):
        for name in long_names:
            if a == name:
                return args[j + 1] if j + 1 < len(args) else ""
            if a.startswith(name + "="):
                return a[len(name) + 1:]
        if a.startswith("-") and not a.startswith("--") and short in a[1:]:
            k = a.index(short, 1)
            return a[k + 1:] or (args[j + 1] if j + 1 < len(args) else "")
    return None


def _skip_options(args, takes):
    i = 0
    while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
        if args[i] == "--":
            return i + 1
        i += _option_span(args, i, takes)
    return i


def _split_words(text):
    """Words of literal text as a shell splits them (quotes honored), or None when a quote is never closed."""
    try:
        return shlex.split(text)
    except ValueError:
        return None


# tmux commands that run shell text, with the options of theirs that take a value.
_TMUX_RUNS = {
    "new-session": {"-c", "-e", "-f", "-F", "-n", "-s", "-t", "-x", "-y"},
    "new-window": {"-c", "-e", "-F", "-n", "-t"},
    "split-window": {"-c", "-e", "-F", "-l", "-p", "-t"},
    "respawn-pane": {"-c", "-e", "-t"},
    "respawn-window": {"-c", "-e", "-t"},
    "run-shell": {"-c", "-d", "-t"},
    "display-popup": {"-b", "-c", "-d", "-e", "-h", "-s", "-S", "-t", "-T", "-w", "-x", "-y"},
    "pipe-pane": {"-t"},
    "if-shell": {"-t"},
    "send-keys": {"-c", "-N", "-t"},
}
_TMUX_ALIASES = {"new": "new-session", "neww": "new-window", "splitw": "split-window", "respawnp": "respawn-pane",
                 "respawnw": "respawn-window", "run": "run-shell", "popup": "display-popup", "pipep": "pipe-pane",
                 "if": "if-shell", "send": "send-keys"}
_TMUX_KEYS_NEWLINE = {"Enter", "C-m", "C-j", "KPEnter"}
_SCREEN_VALUE = {"-c", "-e", "-h", "-p", "-S", "-s", "-t", "-T", "-Logfile"}
_JUST_VALUE = {"-f", "--justfile", "-d", "--working-directory", "--shell", "--shell-arg", "--dotenv-filename",
               "-E", "--dotenv-path", "--color", "--dump-format", "--list-heading", "--list-prefix", "--chooser",
               "--command-color", "--timestamp-format"}
_EXPECT_RUNS = {"spawn", "exec", "system", "send"}
_SPAWN_FLAGS = {"-noecho", "-console", "-nottycopy", "-nottyinit", "-pty"}


def _tmux(args):
    """Shell text tmux runs: tmux -c, and new-session, new-window, send-keys ... (several split by ';')."""
    texts = []
    i = 0
    while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
        if args[i] == "-c" and i + 1 < len(args):
            texts.append((args[i + 1], isinstance(args[i + 1], _Dyn)))
        i += _option_span(args, i, {"-L", "-S", "-f", "-T", "-c"})
    command = []
    for a in args[i:] + [";"]:
        if a != ";":
            command.append(a)
            continue
        if command:
            sub = _TMUX_ALIASES.get(command[0], command[0])
            takes = _TMUX_RUNS.get(sub)
            if takes is not None:
                words = command[1:][_skip_options(command[1:], takes):]
                if sub == "send-keys":
                    words = [";" if w in _TMUX_KEYS_NEWLINE else w for w in words]
                elif sub == "if-shell":
                    words = words[:1]
                if words:
                    texts.append(_text(words))
        command = []
    return texts


def _screen(args):
    """(texts, runs) of screen: a command to run, or screen -X stuff TEXT typed into a window."""
    i = 0
    while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
        if args[i] in ("-ls", "-list", "-wipe", "-v", "-version"):
            return [], []
        if args[i] == "-X":
            rest = args[i + 1:]
            if rest[:1] == ["stuff"] and len(rest) > 1:
                return [_text([rest[1].replace("^M", "\n").replace("\\n", "\n").replace("\\r", "\n")])], []
            if rest[:1] in (["exec"], ["screen"]):
                return [], [rest[1:]]
            return [], []
        i += _option_span(args, i, _SCREEN_VALUE)
    return [], ([args[i:]] if args[i:] else [])


def _expect(args):
    """Shell commands in expect -c scripts: spawn, exec and system, and send (typed into what was spawned)."""
    texts = []
    for j, a in enumerate(args[:-1]):
        if a != "-c":
            continue
        script = args[j + 1]
        if isinstance(script, _Dyn):
            texts.append((script, True))
            continue
        for line in re.split(r"[;\n]", script):
            words = _split_words(line.replace("{", "'").replace("}", "'"))
            if words is None:
                texts.append((line, True))
                continue
            if words and words[0] in _EXPECT_RUNS:
                words = words[1:]
                while words and words[0] in _SPAWN_FLAGS:
                    words = words[1:]
                text = " ".join(words).replace("\r", "\n")
                if text.strip():
                    texts.append((text, False))
    return texts


def _children(name, argv):
    """What a command runs for its words: ([(shell text or None when unread, built at run time)], [argv], whether
    it runs commands it reads on stdin). None when it runs nothing."""
    args = argv[1:]
    if name == "find":
        runs = []
        i = 0
        while i < len(args):
            if args[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                j = i + 1
                while j < len(args) and args[j] not in (";", "+"):
                    j += 1
                # {} is a found path, as unknown here as a substitution's output.
                runs.append([_SUBST if a == "{}" else a for a in args[i + 1:j]])
                i = j
            i += 1
        return [], [r for r in runs if r], False
    if name in ("fd", "fdfind"):
        for j, a in enumerate(args):
            if a in ("-x", "--exec", "-X", "--exec-batch"):
                return [], [args[j + 1:]], False
        return None
    if name == "watch":
        # watch runs its words with sh -c, joined by spaces; -x runs them as a command.
        i = 0
        execs = False
        takes = {"-n", "--interval"}
        while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
            if args[i] == "--":
                i += 1
                break
            execs = execs or args[i] == "--exec" or (
                not args[i].startswith("--") and "x" in _short_letters(args[i], takes))
            i += _option_span(args, i, takes)
        rest = args[i:]
        if not rest:
            return None
        return ([], [rest], False) if execs else ([_text(rest)], [], False)
    if name == "ssh":
        # The words after the host are joined and run by the remote shell; they are checked as if run here.
        i = _skip_options(args, _SSH_VALUE)
        rest = args[i + 1:]
        return ([_text(rest)], [], False) if rest else None
    if name in ("su", "runuser"):
        script = _option_value(args, "c", ("--command", "--session-command"))
        if script is not None:
            return [(script, isinstance(script, _Dyn))], [], False
        return [], [], True
    if name == "flock":
        i = _skip_options(args, _FLOCK_VALUE)
        rest = args[i + 1:]
        if rest and rest[0] in ("-c", "--command"):
            return ([(rest[1], isinstance(rest[1], _Dyn))] if len(rest) > 1 else []), [], False
        return ([], [rest], False) if rest else None
    if name == "script":
        # util-linux: script -c CMD [file], -c only among the leading options; BSD: script [options] file cmd...
        i = 0
        while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
            if args[i] == "--":
                i += 1
                break
            script = _option_value(args[i:i + 2], "c", ("--command",))
            if script is not None:
                return [(script, isinstance(script, _Dyn))], [], False
            i += _option_span(args, i, _SCRIPT_VALUE)
        rest = args[i + 1:]
        return ([], [rest], False) if rest else None
    if name == "parallel":
        i = 0
        template = []
        while i < len(args) and args[i] not in _PARALLEL_SOURCES:
            if not template and args[i].startswith("-"):
                i += _option_span(args, i, _PARALLEL_VALUE)
                continue
            template.append(args[i])
            i += 1
        values = [a for a in args[i:] if a not in _PARALLEL_SOURCES]
        if i >= len(args):
            return ([_text(template)], [], False) if template else ([], [], True)
        texts = []
        for value in values:
            words = template + [value]
            text, dynamic = _text(words)
            if template and "{}" in " ".join(template):
                text = " ".join(template).replace("{}", value)
            texts.append((text, dynamic))
        return texts, [], False
    if name == "trap":
        rest = args[1:] if args[:1] == ["--"] else args
        if len(rest) < 2 or rest[0] in ("-", "", "-l", "-p", "-P"):
            return None
        return [(rest[0], isinstance(rest[0], _Dyn))], [], False
    if name == "tmux":
        return _tmux(args), [], False
    if name == "screen":
        texts, runs = _screen(args)
        return texts, runs, False
    if name == "dtach":
        if not args or args[0] not in ("-n", "-c", "-A", "-N") or len(args) < 3:
            return None
        rest = args[2:]
        i = _skip_options(rest, {"-e", "-r"})
        return ([], [rest[i:]], False) if rest[i:] else None
    if name == "expect":
        return _expect(args), [], False
    if name in ("at", "batch"):
        if any(a in ("-l", "-r", "-d", "-c", "-L") for a in args):
            return None
        files = [args[j + 1] for j, a in enumerate(args[:-1]) if a == "-f"]
        return ([(None, False)], [], False) if files else ([], [], True)
    if name == "launchctl":
        if args[:1] == ["submit"]:
            if "--" in args:
                return [], [args[args.index("--") + 1:]], False
            return [(None, False)], [], False
        if args[:1] in (["asuser"], ["bsexec"]) and len(args) > 2:
            return [], [args[2:]], False
        return None
    if name in ("npm", "npx", "pnpm", "yarn", "bun"):
        return _package_runner(name, args)
    if name == "nix-shell":
        for j, a in enumerate(args[:-1]):
            if a in ("--run", "--command"):
                return [(args[j + 1], isinstance(args[j + 1], _Dyn))], [], False
        return None
    if name == "nix" and args[:1] in (["develop"], ["shell"]):
        for j, a in enumerate(args):
            if a in ("-c", "--command"):
                return [], [args[j + 1:]], False
        return None
    if name == "just":
        # Recipes are not read (like make); just -c / --command runs its words as a command.
        i = 0
        while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
            if args[i] in ("-c", "--command"):
                words = args[i + 1:]
                texts = [_text(words[:1])] if len(words) == 1 and " " in words[0] else []
                return texts, [words] if words else [], False
            i += 3 if args[i] == "--set" else _option_span(args, i, _JUST_VALUE)
        return None
    return None


def _package_runner(name, args):
    """npm exec -c / --call, npx -c, pnpm exec --shell-mode and yarn exec: shell text the package manager runs."""
    if name in ("npm", "pnpm", "bun") and args[:1] not in (["exec"], ["x"]):
        return None
    if name == "yarn":
        if args[:1] != ["exec"]:
            return None
        rest = args[1:]
        return ([_text(rest)], [], False) if rest else None
    rest = args[1:] if name != "npx" else args
    script = _option_value(rest, "c", ("--call", "--shell-mode")) if name != "pnpm" else None
    if name == "pnpm" and any(a in ("-c", "--shell-mode") for a in rest):
        i = _skip_options(rest, {"--filter", "-F", "--workspace-concurrency"})
        return ([_text(rest[i:])], [], False) if rest[i:] else None
    if script is not None:
        return [(script, isinstance(script, _Dyn))], [], False
    return None


# Tools that run a command in a project environment: name -> the subcommands that do. The command follows the
# subcommand's options, or comes after --.
_RUNNERS = {"uv": {"run"}, "poetry": {"run"}, "pipenv": {"run"}, "pdm": {"run"}, "hatch": {"run"}, "rye": {"run"},
            "bundle": {"exec"}, "conda": {"run"}, "mamba": {"run"}, "micromamba": {"run"}, "pixi": {"run"},
            "mise": {"exec", "x"}, "rtx": {"exec", "x"}, "asdf": {"exec"}, "rbenv": {"exec"}, "pyenv": {"exec"},
            "nodenv": {"exec"}, "devbox": {"run"}, "direnv": {"exec"}, "pnpm": {"exec"}, "bun": {"x", "exec"},
            "uvx": None, "pipx": {"run"}, "bunx": None}


def _runner(name, argv):
    """(folders, [argv]) a project runner (uv run, bundle exec, direnv exec DIR ...) starts, or None.

    Options of these tools that take a value are not all known, so when the word before the command is an
    option written without =, the command may also start one word later: both are checked.
    """
    if name not in _RUNNERS:
        return None
    args = argv[1:]
    subs = _RUNNERS[name]
    if subs is not None:
        if not args or args[0] not in subs:
            return None
        args = args[1:]
    dirs = []
    if name == "direnv":
        if not args:
            return None
        dirs, args = [args[0]], args[1:]
    if "--" in args:
        return dirs, [args[args.index("--") + 1:]]
    i = 0
    while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
        i += 1
    if i >= len(args):
        return None
    runs = [args[i:]]
    if i > 0 and "=" not in args[i - 1] and i + 1 < len(args):
        runs.append(args[i + 1:])
    return dirs, runs


_GIT_VALUE = {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env",
              "--attr-source", "--exec-path", "--list-cmds"}
# Git config whose value git runs as shell text (a few take true/false instead).
_GIT_SHELL_KEY = re.compile(
    r"core\.(sshcommand|fsmonitor|editor|pager|gitproxy|alternaterefscommand|askpass)|sequence\.editor|"
    r"diff\.external|pager\..+|(diff|difftool|mergetool)\..+\.(command|textconv|cmd)|merge\..+\.driver|"
    r"filter\..+\.(clean|smudge|process)|interactive\.difffilter|uploadpack\.packobjectshook|"
    r"remote\..+\.(uploadpack|receivepack)|sendemail\.(tocmd|cccmd|smtpserver)|gpg(\..+)?\.program")
_GIT_BOOL = {"", "true", "false", "yes", "no", "on", "off", "1", "0"}
# Variables whose value git runs as shell text.
_GIT_SHELL_ENV = ("GIT_SSH_COMMAND", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER", "GIT_EXTERNAL_DIFF",
                  "GIT_ASKPASS", "GIT_SSH", "GIT_PROXY_COMMAND", "EDITOR", "VISUAL", "PAGER")


def _git_globals(argv):
    """git's options before the subcommand: ([(config key, value or None)], [-C folders], subcommand index)."""
    configs = []
    dirs = []
    i = 1
    while i < len(argv) and argv[i].startswith("-") and len(argv[i]) > 1:
        a = argv[i]
        value = argv[i + 1] if i + 1 < len(argv) else ""
        if a == "-c":
            configs.append(_git_config_pair(value))
        elif a == "-C":
            dirs.append(value)
        elif a == "--config-env" or a.startswith("--config-env="):
            spec = a.split("=", 1)[1] if "=" in a else value
            configs.append((spec.split("=", 1)[0].lower(), None))  # The value is in a variable.
        i += 2 if a in _GIT_VALUE else 1
    return configs, dirs, i


def _git_config_pair(text):
    key, sep, value = text.partition("=")
    if isinstance(text, _Dyn):
        value = _Dyn(value) if sep else _Dyn("")
    return key.lower(), (value if sep else "true")


def _git_env_configs(env):
    """Config set through GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n and GIT_CONFIG_PARAMETERS."""
    configs = []
    for k, v in env.items():
        if k.startswith("GIT_CONFIG_KEY_"):
            value = env.get("GIT_CONFIG_VALUE_" + k[len("GIT_CONFIG_KEY_"):])
            configs.append((v.lower(), value))
    params = env.get("GIT_CONFIG_PARAMETERS")
    if params:
        words = None if isinstance(params, _Dyn) else _split_words(params)
        for word in words if words is not None else ["core.pager=" + params]:
            pair = _git_config_pair(word)
            configs.append((pair[0], _Dyn(pair[1]) if words is None else pair[1]))
    return configs


def _git_runs_value(key, value):
    if key.startswith("credential.") and key.endswith(".helper") or key == "credential.helper":
        return value is None or value.startswith("!") or isinstance(value, _Dyn)
    if not _GIT_SHELL_KEY.fullmatch(key):
        return False
    if (key == "core.fsmonitor" or key.startswith("pager.")) and value is not None and value.lower() in _GIT_BOOL:
        return False
    return True


def _git_sub_texts(sub, rest):
    """Shell text a git subcommand runs: rebase --exec / -x."""
    texts = []
    if sub != "rebase":
        return texts
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--exec", "-x") and i + 1 < len(rest):
            texts.append((rest[i + 1], isinstance(rest[i + 1], _Dyn)))
            i += 2
            continue
        if a.startswith("--exec="):
            texts.append((a[len("--exec="):], isinstance(a, _Dyn)))
        elif a.startswith("-") and not a.startswith("--"):
            letters = _short_letters(a, {"-x", "-s", "-X", "-C", "-S"})
            if letters.endswith("x"):
                value = a[1 + len(letters):] or (rest[i + 1] if i + 1 < len(rest) else "")
                texts.append((value, isinstance(value, _Dyn)))
                i += 1 if a[1 + len(letters):] else 2
                continue
        i += 1
    return texts


def _cron_commands(text):
    """The command of each crontab line: after the five time fields or an @word; variable lines are skipped."""
    commands = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or _is_assignment(line.split(None, 1)[0]):
            continue
        fields = line.split(None, 1 if line.startswith("@") else 5)
        command = fields[-1] if len(fields) == (2 if line.startswith("@") else 6) else ""
        commands.append(re.split(r"(?<!\\)%", command, 1)[0])
    return "\n".join(commands)


# find's options before its roots (BSD and GNU), and the tests that narrow or widen which paths it finds.
_FIND_OPTIONS = {"-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x", "-O0", "-O1", "-O2", "-O3"}
_FIND_TESTS = {"-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-type"}
_FIND_OPERATORS = {"!", "-not", "-o", "-or"}


def _find_found(argv):
    """(roots, predicates) for a find command line: see Cmd.found_roots."""
    args = argv[1:]
    i = 0
    while i < len(args) and args[i] in _FIND_OPTIONS:
        i += 1
    roots = []
    while i < len(args):
        a = args[i]
        if a == "-f" and i + 1 < len(args):
            roots.append(args[i + 1])
            i += 2
            continue
        if a.startswith("-") or a in ("(", "!", ")"):
            break
        roots.append(a)
        i += 1
    predicates = []
    while i < len(args):
        a = args[i]
        if a in ("-exec", "-execdir", "-ok", "-okdir"):
            while i < len(args) and args[i] not in (";", "+"):
                i += 1
        elif a in _FIND_TESTS and i + 1 < len(args):
            predicates.append((a, args[i + 1]))
            i += 1
        elif a in _FIND_OPERATORS:
            predicates.append((a, ""))
        i += 1
    return tuple(roots) or (".",), tuple(predicates)


def _swap(word, old, new):
    """word with old replaced by new, still marked as built at run time when it was."""
    return (_Dyn if isinstance(word, _Dyn) else str)(word.replace(old, new)) if old in word else word


def _xargs_runs(xargs, argv, text, found):
    """([argv] xargs runs, (roots, predicates) or None). The items are known when an echo, printf or heredoc gives
    them; else they are unknown (__SUBST__), with the roots and tests of a find or ls that lists them."""
    replace, plain = xargs[-1]
    items = None
    if len(xargs) == 1 and plain and isinstance(text, str) and not any(ch in text for ch in "'\"\\"):
        items = [w for w in ([line.strip() for line in text.splitlines()] if replace else text.split()) if w]
        if len(items) > MAX_XARGS_ITEMS:
            items = None
    if items is None:
        run = [_swap(a, _XITEM, _SUBST) for a in argv]
        return [run + [_SUBST] if found and not replace else run], found
    if replace:
        return [[_swap(a, _XITEM, item) for a in argv] for item in items] or [argv], None
    return [argv + items], None


def _stage_found(argv):
    """(roots, predicates) when a pipeline stage lists paths with find or ls, else None."""
    name = _base(argv[0]) if argv else ""
    if name in ("find", "gfind"):
        return _find_found(argv)
    if name in ("ls", "gls"):
        return tuple(a for a in argv[1:] if not a.startswith("-")) or (".",), (("ls", ""),)
    return None


def _stage_output(argv, stdin_text, piped_text):
    """What a pipeline stage prints, when it is literal text known from the command line; else None."""
    name = _base(argv[0]) if argv else ""
    args = argv[1:]
    if name in ("cat", "tee"):
        if name == "cat" and any(not a.startswith("-") for a in args):
            return None  # cat of a file prints text checkrein cannot see.
        if stdin_text:
            return stdin_text
        return None if piped_text is _NO_PIPE else piped_text
    if name in ("echo", "printf"):
        if any("$" in a or "`" in a or _SUBST in a or _ARITH in a for a in args):
            return None
        # printf formats and escapes (%s, \163, \x20), and echo escapes in shells that expand them, change the
        # text; only a plain \n is decoded here, anything else is unknown.
        if name == "printf" and args and args[0] in ("%s\\n", "%s\n", "%s "):
            if any("%" in a or "\\" in a for a in args[1:]):
                return None
            # printf repeats its format for each argument.
            return "".join(a + ("\n" if args[0] != "%s " else " ") for a in args[1:])
        if name == "printf" and any("%" in a for a in args):
            return None
        if any("\\" in a.replace("\\n", "") for a in args):
            return None
        while name == "echo" and args and args[0] in ("-n", "-e", "-E", "-ne", "-en"):
            args = args[1:]
        return " ".join(args).replace("\\n", "\n") + "\n"
    return None


def _reads_stdin(argv):
    """True when a shell takes its script from stdin: no script file, or -s, or -."""
    if _base(argv[0]) == "busybox" and len(argv) > 1 and _base(argv[1]) in SHELLS:
        argv = argv[1:]
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "-":
            return True
        if a == "--":
            return i + 1 >= len(argv)
        if a.startswith("-") and not a.startswith("--") and "s" in a[1:]:
            return True
        if a in _SHELL_VALUE_OPTIONS:
            i += 2
            continue
        if a.startswith(("-", "+")):
            i += 1
            continue
        return False  # A script file: stdin is its data.
    return True


def _shell_c_arg(argv):
    for i, a in enumerate(argv[1:], 1):
        if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]):
            return argv[i + 1] if i + 1 < len(argv) else ""
    return None


def short_flags(arg, takes_value=""):
    """Letters in a short-option cluster like -fd, stopping at a value-taking letter."""
    if not arg.startswith("-") or arg.startswith("--") or len(arg) < 2:
        return ""
    letters = []
    for ch in arg[1:]:
        letters.append(ch)
        if ch in takes_value:
            break
    return "".join(letters)

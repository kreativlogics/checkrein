"""Shell-style globs: brace expansion and matching that never backtracks without bound.

Used for the MCP tool lists in the config and for paths that a shell command names with glob characters.
Matching is the two-pointer wildcard walk (at most pattern length x name length steps), so no pattern can
stall the hook the way a regex can.
"""

import os
import re

MAX_EXPANSIONS = 256
# Expansion steps one hook call may spend on all the words of a command together.
BUDGET_STEPS = 20000


class _TooMany(Exception):
    pass


_STAR = object()


def _matching_brace(s, i):
    """Index of the } closing the { at i, and the top-level comma positions inside; (-1, []) when unbalanced."""
    depth = 0
    commas = []
    j = i
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j, commas
        elif c == "," and depth == 1:
            commas.append(j)
        j += 1
    return -1, []


def _sequence(body):
    """Items of a {1..5} or {a..e} sequence, or None."""
    parts = body.split("..")
    if len(parts) not in (2, 3):
        return None
    lo, hi = parts[0], parts[1]
    step = 1
    if len(parts) == 3:
        try:
            step = abs(int(parts[2])) or 1
        except ValueError:
            return None
    try:
        a, b = int(lo), int(hi)
        nums = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        if len(nums) > MAX_EXPANSIONS:
            raise _TooMany()
        return [str(n) for n in nums]
    except ValueError:
        pass
    if len(lo) == 1 and len(hi) == 1:
        a, b = ord(lo), ord(hi)
        codes = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        if len(codes) > MAX_EXPANSIONS:
            raise _TooMany()  # Checked before the list is built: {a..<last code point>} is over a million.
        return [chr(n) for n in codes]
    return None


def _expand(s, start, out, budget):
    if budget is not None:
        budget["left"] -= 1
        if budget["left"] < 0:
            budget["spent"] = True
            raise _TooMany()
    i = start
    while True:
        i = s.find("{", i)
        if i > 0 and s[i - 1] == "\\":
            i += 1
            continue
        j, commas = _matching_brace(s, i) if i != -1 else (-1, [])
        if j == -1:
            out.append(s)
            if len(out) > MAX_EXPANSIONS:
                raise _TooMany()
            return
        if commas:
            bounds = [i] + commas + [j]
            items = [s[bounds[k] + 1:bounds[k + 1]] for k in range(len(bounds) - 1)]
        else:
            items = _sequence(s[i + 1:j])
            if items is None:
                i += 1  # A {x} with no comma stays as it is; braces nested in it may still expand.
                continue
        for item in items:
            _expand(s[:i] + item + s[j + 1:], i, out, budget)
        return


def new_budget(steps=BUDGET_STEPS):
    """A work allowance shared by many expand_braces calls; "spent" turns True once it runs out."""
    return {"left": steps, "spent": False}


def expand_braces(text, budget=None):
    """The words a shell's brace expansion makes of text, or None when that is more than MAX_EXPANSIONS or the
    shared budget runs out."""
    if "{" not in text:
        return [text]
    out = []
    try:
        _expand(text, 0, out, budget)
    except _TooMany:
        return None
    except RecursionError:
        return None
    return out


def _tokens(pattern, fold):
    """Pattern as a list of _STAR, ("?",), ("[", chars, ranges, negate) or a literal character."""
    toks = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if not toks or toks[-1] is not _STAR:
                toks.append(_STAR)
            i += 1
        elif c == "?":
            toks.append(("?",))
            i += 1
        elif c == "[":
            j = i + 1
            negate = j < n and pattern[j] in "!^"
            if negate:
                j += 1
            k = j + 1 if j < n and pattern[j] == "]" else j
            while k < n and pattern[k] != "]":
                k += 1
            if k >= n:
                toks.append(fold("["))  # An unclosed [ is a plain character.
                i += 1
                continue
            body = pattern[j:k]
            chars = set()
            ranges = []
            m = 0
            while m < len(body):
                if m + 2 < len(body) and body[m + 1] == "-":
                    ranges.append((fold(body[m]), fold(body[m + 2])))
                    m += 3
                else:
                    chars.add(fold(body[m]))
                    m += 1
            toks.append(("[", chars, ranges, negate))
            i = k + 1
        else:
            if c == "\\" and i + 1 < n:
                i += 1
                c = pattern[i]
            toks.append(fold(c))
            i += 1
    return toks


def _one(tok, ch):
    if isinstance(tok, str):
        return tok == ch
    if tok[0] == "?":
        return True
    _kind, chars, ranges, negate = tok
    hit = ch in chars or any(lo <= ch <= hi for lo, hi in ranges)
    return hit != negate


def _match_one(pattern, name, fold):
    toks = _tokens(pattern, fold)
    s = fold(name)
    pi = si = 0
    star = -1
    mark = 0
    while si < len(s):
        if pi < len(toks) and toks[pi] is _STAR:
            star = pi
            mark = si
            pi += 1
        elif pi < len(toks) and _one(toks[pi], s[si]):
            pi += 1
            si += 1
        elif star != -1:
            pi = star + 1
            mark += 1
            si = mark
        else:
            return False
    while pi < len(toks) and toks[pi] is _STAR:
        pi += 1
    return pi == len(toks)


def match(pattern, name, ignore_case=True):
    """True when the whole of name matches the glob pattern (* ? [...] [!...] {a,b})."""
    fold = (lambda x: x.lower()) if ignore_case else (lambda x: x)  # noqa: E731
    alternatives = expand_braces(pattern)
    if alternatives is None:
        return False
    return any(_match_one(p, name, fold) for p in alternatives)


# Characters that make a shell word a pattern. A ( ... ) pair counts too: zsh reads (a|b) as a glob.
# ${...} expansions and the {} placeholder of xargs -I and find -exec are values, like $x, not brace globs.
_DYNAMIC = re.compile(r"\$\{[^{}]*\}|\{\}")


_MAGIC = re.compile(r"[*?\[]")


def has_magic(word):
    if "{" in word:
        word = _DYNAMIC.sub("", word)
        if "{" in word and "}" in word:
            return True
    return _MAGIC.search(word) is not None or ("(" in word and ")" in word)


def _component_may_match(pat, name, ignore_case):
    fold = (lambda x: x.lower()) if ignore_case else (lambda x: x)  # noqa: E731
    if not has_magic(pat):
        return fold(pat) == fold(name)
    if any(c in pat for c in "{}()"):
        return True  # Braces left over, or zsh alternation: can't tell, so assume it matches.
    if name.startswith(".") and not pat.startswith("."):
        return False  # Shells don't let a wildcard match a leading dot.
    return _match_one(pat, name, fold)


def _may_reach(pattern, root, ignore_case):
    pc = [c for c in pattern.split(os.sep) if c]
    rc = [c for c in root.split(os.sep) if c]
    for i in range(min(len(pc), len(rc))):
        if pc[i] == "**":
            return True  # Matches any depth, so anything below this point.
        if not _component_may_match(pc[i], rc[i], ignore_case):
            return False
    return True


def _forms(pattern):
    """The pattern, and the same with its literal leading folders resolved through symlinks."""
    parts = pattern.split(os.sep)
    k = 0
    while k < len(parts) and not has_magic(parts[k]):
        k += 1
    prefix = os.sep.join(parts[:k]) or os.sep
    try:
        real = os.path.realpath(prefix)
    except OSError:
        return [pattern]
    rest = os.sep.join(parts[k:])
    return [pattern, os.path.join(real, rest) if rest else real]


def path_may_reach(pattern, root, ignore_case=False):
    """True when a glob path could name root, something inside it, or a folder that holds it.

    ignore_case: the file system holding root treats names that differ only in case as the same.
    """
    roots = {os.path.normpath(root)}
    try:
        roots.add(os.path.realpath(root))
    except OSError:
        pass
    return any(_may_reach(p, r, ignore_case) for p in _forms(pattern) for r in roots)


def path_may_be(pattern, target, ignore_case=False):
    """True when a glob path could name exactly target."""
    targets = {os.path.normpath(target)}
    try:
        targets.add(os.path.realpath(target))
    except OSError:
        pass
    for p in _forms(pattern):
        pc = [c for c in p.split(os.sep) if c]
        for t in targets:
            tc = [c for c in t.split(os.sep) if c]
            if "**" in pc and _may_reach(p, t, ignore_case):
                return True
            if len(pc) == len(tc) and _may_reach(p, t, ignore_case):
                return True
    return False

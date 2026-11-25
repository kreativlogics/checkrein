"""Run every rule group and combine the hits into one decision."""

from ..context import LEVELS, Hit
from .. import globs
from . import git, mcp, sec, skl, slf

GROUPS = (git, sec, skl, slf, mcp)


class Decision(object):
    def __init__(self, level, hits, errors=()):
        self.level = level  # off (no decision), ask or deny
        self.hits = hits
        self.errors = list(errors)  # Checks that failed; the caller applies fail_mode.

    def reason(self, unattended=False):
        lines = []
        for hit in self.hits:
            # Where no one can confirm, an ask is a deny, and the text says what happens.
            level = "deny" if unattended and hit.level == "ask" else hit.level
            if hit.rule is None:
                lines.append("checkrein (%s): %s" % (level, hit.reason))
            else:
                lines.append("checkrein %s (%s): %s" % (hit.rule, level, hit.reason))
        if unattended and any(h.level == "ask" for h in self.hits):
            lines.append("No one can confirm in this permission mode, so this is denied.")
        lines.append("Rules and levels: /checkrein:config explain <rule>.")
        return "\n".join(lines)


_WIDE_BRACES = ("A word in the command has too many expansions (its {a,b} groups make more than %d words), so "
                "checkrein reads it as any path it could name.")


def _wide_braces(parsed):
    """True when a word kept its {a,b} groups because they make more words than checkrein expands."""
    for cmd in parsed.cmds:
        for arg in cmd.args:
            if "{" in arg and "}" in arg and globs.expand_braces(arg) is None:
                return True
    return False


def _rank(level):
    return LEVELS.index(level) if level in LEVELS else 0


def evaluate(ctx):
    hits = []
    errors = []
    # An MCP tool with a command field may run it in a shell: it is judged as an MCP call and as Bash.
    views = [ctx]
    if ctx.tool_name.startswith("mcp__") and ctx.shell_command is not None:
        views.append(ctx.as_shell())
    # Each group runs on its own, so one that fails can't take away what the others found.
    for view in views:
        for group in GROUPS:
            try:
                hits.extend(group.check(view))
            except Exception as exc:  # noqa: BLE001 - reported, and fail_mode applies.
                errors.append("%s: %s" % (type(exc).__name__, exc))
    ctx = views[-1]
    kept = []
    seen = set()
    for hit in hits:
        configured = ctx.eff.level(hit.rule)
        if configured == "off":
            continue  # Off means off, even for the always-deny cases.
        level = hit.level or configured
        if hit.cap and _rank(level) > _rank(hit.cap):
            level = hit.cap
        if level not in ("ask", "deny"):
            continue
        hit.level = level
        key = (hit.rule, hit.reason)
        if key in seen:
            continue
        seen.add(key)
        kept.append(hit)
    try:
        parsed = ctx.parsed
    except Exception as exc:  # noqa: BLE001 - reported, and fail_mode applies.
        parsed = None
        errors.append("%s: %s" % (type(exc).__name__, exc))
    if parsed is not None and parsed.problem:
        # A command checkrein could not read in full is judged here, not by a rule, so no rule level can let it
        # through unread.
        kept.append(Hit(None, parsed.problem, level=parsed.problem_level))
    errors = list(dict.fromkeys(errors))
    if not kept:
        return Decision("off", [], errors)
    top = max(kept, key=lambda h: _rank(h.level)).level
    if parsed is not None and _wide_braces(parsed):
        # The word was judged as written, as any path it could name; the reason says why it was not expanded.
        kept.append(Hit(None, _WIDE_BRACES % globs.MAX_EXPANSIONS, level=top))
    kept.sort(key=lambda h: (-_rank(h.level), h.rule or ""))
    return Decision(top, kept, errors)

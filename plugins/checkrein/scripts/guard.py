#!/usr/bin/env python3
"""checkrein hook entry point.

  guard.py pre      PreToolUse: decide allow (no output), ask or deny.
  guard.py session  SessionStart: config notes and the skill/plugin drift report.

Reads the hook payload as JSON on stdin. Stdlib only, Python 3.9+.
"""

import json
import os
import signal
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Keep the installed plugin folder free of .pyc files, so it still hashes and scans as published. The hook runs on
# every tool call, so its bytecode is cached in the data folder instead of not at all.
if os.environ.get("CLAUDE_PLUGIN_DATA"):
    sys.pycache_prefix = os.path.join(os.environ["CLAUDE_PLUGIN_DATA"], "pycache")
else:
    sys.dont_write_bytecode = True
sys.path.insert(0, HERE)

PLUGIN_ROOT = os.path.dirname(HERE)
CONTEXT_LIMIT = 9000
# Seconds a check may take. Past it the call is denied with a clear reason, rather than left to the host's hook
# timeout, which would let it through.
DEADLINE = 5.0


def _emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.write("\n")


def _pre_output(level, reason):
    _emit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": level,
                                  "permissionDecisionReason": reason}})


_FAIL_ORDER = ("allow", "ask", "deny")


def _fail_mode(payload):
    """The fail_mode that applies: read leniently, since the config may be what failed.

    The strictest value set by the plugin option or the user config counts (ask when neither is set); the project
    file may only make it stricter. Ask becomes deny when no one can confirm.
    """
    project = os.environ.get("CLAUDE_PROJECT_DIR") or (payload or {}).get("cwd")
    own = [os.environ.get("CLAUDE_PLUGIN_OPTION_FAIL_MODE", "").strip(), _file_fail_mode(_user_config_path())]
    own = [m for m in own if m in _FAIL_ORDER]
    mode = max(own, key=_FAIL_ORDER.index) if own else "ask"
    project_mode = _file_fail_mode(os.path.join(project, ".checkrein", "config.json")) if project else None
    if project_mode in _FAIL_ORDER and _FAIL_ORDER.index(project_mode) > _FAIL_ORDER.index(mode):
        mode = project_mode
    if mode == "ask" and (payload or {}).get("permission_mode") in ("dontAsk", "bypassPermissions"):
        mode = "deny"
    return mode


def _fail(payload, message):
    """checkrein itself failed: apply fail_mode (allow, ask, deny)."""
    mode = _fail_mode(payload)
    if mode == "allow":
        return
    _pre_output(mode, "checkrein could not check this call: %s Fix it with /checkrein:config doctor. "
                      "(fail_mode is %s.)" % (message, mode))


def _user_config_path():
    try:
        from checkrein import context
        data_dir = context.default_data_dir(os.path.expanduser("~"))
    except Exception:  # noqa: BLE001 - fall back to the variable Claude Code sets.
        data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    return os.path.join(data_dir, "config.json") if data_dir else None


def _file_fail_mode(path):
    if not path:
        return None
    try:
        # Read without blocking: a FIFO or device here must not hang the hook.
        from checkrein import ledger
        value = json.loads(ledger.read_regular(path, 256 * 1024)).get("fail_mode")
    except Exception:  # noqa: BLE001 - a broken file is what we are reporting.
        return None
    return value if isinstance(value, str) else None


_FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_TEXT_FIELDS = {"Bash": ("command",), "Write": ("file_path", "content"),
                "Edit": ("file_path", "old_string", "new_string"), "MultiEdit": ("file_path",),
                "NotebookEdit": ("notebook_path", "new_source")}


def _malformed(payload):
    """Why a checked tool's input has a shape checkrein can't read, or None."""
    tool, ti = payload.get("tool_name"), payload.get("tool_input")
    if not isinstance(tool, str):
        return "the tool name is not text"
    command = ti.get("command") if isinstance(ti, dict) else None
    if tool not in _FILE_TOOLS and isinstance(command, list) and not all(isinstance(w, str) for w in command):
        # A list of words is judged as a shell command, so every word must be text. A command of another shape
        # (an object) on a tool other than Bash means that tool is not a shell, and it is judged as itself.
        return "the command is not text"
    if tool not in _TEXT_FIELDS and not tool.startswith("mcp__"):
        return None
    if not isinstance(ti, dict):
        return "the tool input is not an object"
    for field in _TEXT_FIELDS.get(tool, ()):
        if ti.get(field) is not None and not isinstance(ti[field], str):
            return "%s is not text" % field
    if tool == "Bash" and not isinstance(ti.get("command"), str):
        return "the command is not text"
    if tool == "MultiEdit":
        edits = ti.get("edits")
        if not isinstance(edits, list) or not all(
                isinstance(e, dict) and all(isinstance(e.get(k), str) for k in ("old_string", "new_string"))
                for e in edits):
            return "edits is not a list of text edits"
    return None


class _OutOfTime(BaseException):
    """Raised by the deadline alarm. Not an Exception, so no check's error handling can swallow it."""


def _ring(_signum, _frame):
    raise _OutOfTime()


def _arm(seconds):
    if hasattr(signal, "setitimer"):
        signal.signal(signal.SIGALRM, _ring)
        signal.setitimer(signal.ITIMER_REAL, seconds)


def _disarm():
    if hasattr(signal, "setitimer"):
        signal.setitimer(signal.ITIMER_REAL, 0)


def pre(payload):
    from checkrein import cfg, context, rules

    if not isinstance(payload, dict) or not payload.get("tool_name"):
        return _fail(payload, "the hook input had no tool name.")
    bad = _malformed(payload)
    if bad:
        # A known tool with input of the wrong shape can't be checked, and Claude Code would not run it as is.
        return _pre_output("deny", "checkrein can't read this call: %s." % bad)
    home = os.path.expanduser("~")
    data_dir = context.default_data_dir(home)
    project = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd")
    try:
        eff = cfg.resolve(data_dir, project)
    except cfg.ConfigError as exc:
        return _fail(payload, "%s" % exc)
    ctx = context.Ctx(payload, eff, home=home, data_dir=data_dir, plugin_root=PLUGIN_ROOT)
    decision = rules.evaluate(ctx)
    level = decision.level
    if level == "ask" and ctx.unattended:
        level = "deny"
    reason = decision.reason(unattended=ctx.unattended) if decision.hits else ""
    if decision.errors:
        # A check failed. What the other checks found stands; fail_mode decides only when it is stricter.
        mode = _fail_mode(payload)
        if _FAIL_ORDER.index(mode) > _FAIL_ORDER.index(level if level in _FAIL_ORDER else "allow"):
            level = mode
        reason = (reason + "\n" if reason else "") + (
            "checkrein could not finish every check (%s). Fix it with /checkrein:config doctor. (fail_mode is %s.)"
            % ("; ".join(decision.errors), mode))
    if level not in ("ask", "deny"):
        return
    if eff.project_error:
        reason += "\n" + cfg.PROJECT_IGNORED_NOTE
    _pre_output(level, reason)


def session(payload):
    from checkrein import cfg, context, ledger

    home = os.path.expanduser("~")
    data_dir = context.default_data_dir(home)
    project = os.environ.get("CLAUDE_PROJECT_DIR") or (payload or {}).get("cwd")
    lines = []
    try:
        eff = cfg.resolve(data_dir, project)
    except cfg.ConfigError as exc:
        _emit({"systemMessage": "checkrein: config problem: %s Run /checkrein:config doctor." % exc})
        return
    lines.extend("checkrein: %s" % n for n in eff.notes)
    if eff.level("SKL05") == "report":
        lines.extend(_drift_lines(ledger, data_dir, home, project, eff))
    if not lines:
        return
    text = "\n".join(lines)
    if len(text) > CONTEXT_LIMIT:
        text = text[:CONTEXT_LIMIT] + "\n... (cut; run /checkrein:status for the full report)"
    _emit({"systemMessage": text,
           "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}})


def _drift_lines(ledger, data_dir, home, project, eff):
    try:
        report = ledger.drift(data_dir, home, project, eff.get("extra_skill_roots") or [])
    except ledger.LedgerError as exc:
        return ["checkrein: %s Plugin installs are refused until it is fixed." % exc]
    if report is None:
        items = ledger.inventory(home, project, eff.get("extra_skill_roots") or [])
        if not items:
            return []
        return ["checkrein: no install ledger yet. %d installed skill(s) and plugin(s) are not recorded. "
                "Run /checkrein:status to review them and record what you trust." % len(items)]
    lines = []
    if report["changed"]:
        lines.append("checkrein: changed since approval: %s. Review with /checkrein:status."
                     % ", ".join(report["changed"][:15]))
    if report["unvetted"]:
        lines.append("checkrein: installed but never vetted: %s. Review with /checkrein:status."
                     % ", ".join(report["unvetted"][:15]))
    if report["bound"]:
        lines.append("checkrein: first look at newly installed plugin code: %s." % ", ".join(report["bound"][:15]))
    if report["missing"]:
        lines.append("checkrein: approved but no longer installed: %s." % ", ".join(report["missing"][:15]))
    return lines


# JSON nested deeper than this is refused before it is parsed: deep nesting crashes json.loads with a
# RecursionError, and no real tool input comes near it.
MAX_DEPTH = 200
_JSON_TOKENS = None


def _too_deep(raw, limit=MAX_DEPTH):
    """True when raw JSON nests arrays or objects deeper than limit. Brackets inside strings don't count."""
    global _JSON_TOKENS
    if raw.count("[") + raw.count("{") <= limit:
        return False
    if _JSON_TOKENS is None:
        import re
        _JSON_TOKENS = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]')
    depth = 0
    for match in _JSON_TOKENS.finditer(raw):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            if depth > limit:
                return True
        elif token in ("]", "}"):
            depth -= 1
    return False


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    payload = None
    try:
        raw = sys.stdin.read()
        if _too_deep(raw):
            if mode == "pre":
                _pre_output("deny", "checkrein can't read this call: the hook input is nested more than %d levels "
                                    "deep." % MAX_DEPTH)
            return 0
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except ValueError:
            payload = None
        if mode == "pre":
            if payload is None:
                return _fail({}, "the hook input was not valid JSON.")
            _arm(DEADLINE)
            try:
                pre(payload)
            finally:
                _disarm()
        elif mode == "session":
            session(payload or {})
    except _OutOfTime:
        _pre_output("deny", "checkrein ran out of time (%g s) checking this call, so it is denied. Split it into "
                            "smaller commands." % DEADLINE)
    except BaseException as exc:  # noqa: BLE001 - every crash, SystemExit too, goes through fail_mode.
        _crashed(mode, payload, exc)
    return 0


def _crashed(mode, payload, exc):
    """Report a crash with a decision, so the hook never exits without one."""
    try:
        if mode == "pre":
            _fail(payload if isinstance(payload, dict) else {}, "internal error (%s: %s)."
                  % (type(exc).__name__, str(exc)[:300]))
        else:
            _emit({"systemMessage": "checkrein: session check failed (%s). Run /checkrein:config doctor."
                                    % type(exc).__name__})
    except BaseException:  # noqa: BLE001 - fail_mode itself failed, so the strictest answer stands.
        if mode == "pre":
            _pre_output("deny", "checkrein could not check this call (%s), so it is denied." % type(exc).__name__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

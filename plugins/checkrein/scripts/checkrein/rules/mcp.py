"""MCP01-MCP02: outbound MCP tool calls."""

import json
import re

from ..context import Hit
from .. import globs
from .. import secrets

PAYLOAD_LIMIT = 700
# Text past the shown part that is still masked, so a secret cut by the limit is hidden whole. Every secret pattern
# that needs text after its start matches within this much.
_MASK_MARGIN = 16384
# Verbs that make a tool a write wherever they stand in its name (slack_send_message, chat_postMessage,
# notion-create-pages, issue_create, batch).
WRITE_VERBS = {
    "create", "update", "delete", "remove", "edit", "add", "post", "send", "transition", "merge", "accept", "comment",
    "publish", "write", "save", "upload", "move", "archive", "assign", "close", "reopen", "invite", "share", "set",
    "apply", "fork", "link", "batch", "insert", "put", "patch", "push", "submit", "approve", "reply", "forward",
    "rename", "replace", "modify", "append", "schedule", "cancel", "revoke", "grant", "deploy", "import", "trigger",
    "upsert", "mutate", "destroy", "drop", "purge", "unlink", "unassign", "unshare", "transfer", "restore",
}
_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def check(ctx):
    if not ctx.tool_name.startswith("mcp__"):
        return []
    hits = []
    payload = json.dumps(ctx.tool_input, ensure_ascii=False, sort_keys=True)
    # Each string is scanned as sent: in the JSON text a newline is the two characters \n, which hides a token's
    # start from the scanner.
    found = [h for text in _strings(ctx.tool_input) for h in secrets.scan_text(text)
             if h.confidence == secrets.HIGH or h.kind == "url-password"]
    if found:
        kinds = sorted(set(h.label for h in found))
        hits.append(Hit("MCP02", "This %s call would send what looks like a %s to another system."
                        % (ctx.tool_name, " and a ".join(kinds))))
    if ctx.eff.level("MCP01") != "off" and _is_write(ctx) and not _is_routine(ctx):
        # Only the part shown is masked: masking a large payload whole takes longer than the hook may run.
        shown = secrets.mask(payload[:PAYLOAD_LIMIT + _MASK_MARGIN])
        if len(payload) > PAYLOAD_LIMIT:
            shown = shown[:PAYLOAD_LIMIT] + " ... (%d more characters)" % (len(payload) - PAYLOAD_LIMIT)
        hits.append(Hit("MCP01", "%s writes to another system. It would send: %s" % (ctx.tool_name, shown)))
    return hits


def _strings(value):
    """Every string key and value in a tool input, nested lists and objects included."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def _any(patterns, name):
    return any(globs.match(pat, name) for pat in patterns if isinstance(pat, str))


def _is_write(ctx):
    return _any(ctx.eff.get("mcp_write_tools") or [], ctx.tool_name) or has_write_verb(ctx.tool_name)


def has_write_verb(tool_name):
    """True when the tool's own name (after the server) holds a write verb as a whole word, split at _, -, . and
    camelCase."""
    name = tool_name.split("__")[-1]
    return any(w.lower() in WRITE_VERBS for w in _WORDS.findall(name))


def _is_routine(ctx):
    return _any(ctx.eff.get("mcp_routine") or [], ctx.tool_name)

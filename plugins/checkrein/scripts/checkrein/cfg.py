"""Layered configuration: defaults < user < project.

- User layer: the plugin's userConfig values (CLAUDE_PLUGIN_OPTION_*), then
  <data dir>/config.json. Only this layer may loosen anything.
- Project layer: <project>/.checkrein/config.json, committed with the repo.
  Safety keys only tighten (off < ask < deny; lists union). Keys that loosen
  (secret_ignore_paths) or run something (scanner) count only once approved.
  A loosening that is ignored is reported, never applied silently.
"""

import difflib
import json
import os
import re
import shlex

from . import approve
from . import ledger
from . import globs
from . import secrets

SUPPORTED_VERSION = 1
PRESETS = ("relaxed", "standard", "strict")
FAIL_MODES = ("allow", "ask", "deny")
SECRET_SCANNERS = ("auto", "builtin", "gitleaks")

_HERE = os.path.dirname(os.path.abspath(__file__))

# key -> (type, class). Classes: preference, safety-level, safety-union, loosen-approved, loosen-user, exec.
SCHEMA = {
    "version": ("int", "meta"),
    "preset": ("preset", "preset"),
    "fail_mode": ("fail_mode", "safety-order"),
    "rules": ("rules", "safety-level"),
    "protected_branches": ("list", "safety-union"),
    "extra_skill_roots": ("list", "safety-union"),
    "extra_installers": ("list", "safety-union"),
    "mcp_write_tools": ("list", "safety-union"),
    "secret_ignore_paths": ("list", "loosen-approved"),
    "mcp_routine": ("list", "loosen-user"),
    "scanner": ("scanner", "exec"),
    "secret_scanner": ("secret_scanner", "preference"),
}

# Keys whose values are folders on disk.
PATH_KEYS = ("extra_skill_roots",)
# NUL, newlines and other control characters: no config value needs them, and a path holding one breaks os calls.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

DESCRIPTIONS = {
    "version": "Config format version. Leave at 1.",
    "preset": "relaxed, standard or strict. Sets every rule's level; rules below it override single rules.",
    "fail_mode": "What happens if checkrein itself fails: ask, deny or allow. A project can only make it stricter.",
    "rules": "Per-rule levels, e.g. {\"GIT06\": \"ask\"}. Levels are off, ask or deny (SKL05: off or report).",
    "protected_branches": "Branches a force push is always denied on. Globs allowed (release/*). Lists from every layer add up.",
    "extra_skill_roots": "More folders treated as skill folders by the install gate.",
    "extra_installers": "More package names treated as skill installers by SKL03.",
    "mcp_write_tools": "Globs for MCP tool names that MCP01 treats as writes, e.g. mcp__*__create* or mcp__jira__{create,edit}_issue (whole name, any case).",
    "secret_ignore_paths": "Path globs the secret rules skip (test fixtures). In a project file they apply only after you approve them.",
    "mcp_routine": "Globs for MCP write tools that MCP01 lets through with no question, e.g. *__set_session_title. Your own config only; ignored in project files.",
    "scanner": "{\"command\": [..., \"{path}\", ...], \"env\": [\"VAR\", ...]} third-party scanner for the install gate. It sees only a basic environment plus the variables named in env. In a project file it runs only after you approve it.",
    "secret_scanner": "auto (gitleaks when installed, else built-in), builtin or gitleaks. Used by SEC03.",
}


_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Keys holding globs the hook matches against every MCP tool name. They are globs, not regexes: a regex can
# backtrack for longer than the hook's timeout, and Claude Code then lets the call through. Glob matching is linear.
GLOB_KEYS = ("mcp_write_tools", "mcp_routine")
GLOB_MAX_LENGTH = 600
_GLOB_CHARS = re.compile(r"^[A-Za-z0-9_\-*?\[\]!{},]+$")
CONFIG_MAX_BYTES = 256 * 1024


PROJECT_IGNORED_NOTE = ("The project config (.checkrein/config.json) is invalid, so all of it is ignored; your own "
                        "config and the defaults apply. Run /checkrein:config doctor to see what is wrong.")


class ConfigError(Exception):
    pass


def load_registry():
    with open(os.path.join(_HERE, "rules.json")) as fh:
        return json.load(fh)


def _order(levels, value):
    return levels.index(value) if value in levels else -1


def _hint(key, choices):
    close = difflib.get_close_matches(key, list(choices), n=1)
    return " Did you mean %r?" % close[0] if close else ""


def validate(data, where, registry):
    """Raise ConfigError with path, expected, got and the fix."""
    if not isinstance(data, dict):
        raise ConfigError("%s: expected a JSON object, got %s." % (where, type(data).__name__))
    version = data.get("version", SUPPORTED_VERSION)
    if not isinstance(version, int):
        raise ConfigError("%s: version: expected an integer, got %r." % (where, version))
    if version > SUPPORTED_VERSION:
        raise ConfigError("%s: version %d is newer than this checkrein understands (%d). Update the plugin."
                          % (where, version, SUPPORTED_VERSION))
    rules = registry["rules"]
    for key, value in data.items():
        if key not in SCHEMA:
            raise ConfigError("%s: unknown key %r.%s" % (where, key, _hint(key, SCHEMA)))
        kind = SCHEMA[key][0]
        if kind == "preset" and value not in PRESETS:
            raise ConfigError("%s: preset: expected one of %s, got %r." % (where, ", ".join(PRESETS), value))
        if kind == "fail_mode" and value not in FAIL_MODES:
            raise ConfigError("%s: fail_mode: expected one of %s, got %r." % (where, ", ".join(FAIL_MODES), value))
        if kind == "secret_scanner" and value not in SECRET_SCANNERS:
            raise ConfigError("%s: secret_scanner: expected one of %s, got %r."
                              % (where, ", ".join(SECRET_SCANNERS), value))
        if kind == "list":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ConfigError("%s: %s: expected a list of strings." % (where, key))
            if key in PATH_KEYS:
                for index, path in enumerate(value):
                    if not path.startswith(("/", "~")):
                        raise ConfigError("%s: %s[%d]: expected an absolute path (/... or ~/...), got %r."
                                          % (where, key, index, path))
            if key in GLOB_KEYS:
                for index, pattern in enumerate(value):
                    problem = glob_problem(pattern)
                    if problem:
                        raise ConfigError("%s: %s[%d]: %s" % (where, key, index, problem))
        if kind == "rules":
            if not isinstance(value, dict):
                raise ConfigError("%s: rules: expected an object of rule IDs to levels." % where)
            for rid, level in value.items():
                if rid not in rules:
                    raise ConfigError("%s: rules: unknown rule %r.%s" % (where, rid, _hint(rid, rules)))
                if level not in rules[rid]["levels"]:
                    raise ConfigError("%s: rules.%s: expected one of %s, got %r."
                                      % (where, rid, ", ".join(rules[rid]["levels"]), level))
        if kind == "scanner":
            cmd = value.get("command") if isinstance(value, dict) else None
            names = value.get("env", []) if isinstance(value, dict) else None
            if not isinstance(value, dict) or set(value) - {"command", "env"} or not isinstance(cmd, list) \
                    or not cmd or not all(isinstance(c, str) for c in cmd) or not isinstance(names, list) \
                    or not all(isinstance(n, str) and _ENV_NAME.match(n) for n in names):
                raise ConfigError("%s: scanner: expected {\"command\": [\"tool\", \"arg\", ...], "
                                  "\"env\": [\"VAR_NAME\", ...]} (env is optional)." % where)
    for text in _strings(data):
        if _CONTROL.search(text):
            raise ConfigError("%s: a value holds a control character (%r). Config values are plain text."
                              % (where, _CONTROL.search(text).group(0)))
        if secrets.scan_text(text, high_only=True):
            raise ConfigError("%s: a value looks like a real secret. Config files never hold secrets." % where)
    return data


def glob_problem(pattern):
    """Why a configured MCP tool glob is refused, or None."""
    if len(pattern) > GLOB_MAX_LENGTH:
        return "pattern is longer than %d characters." % GLOB_MAX_LENGTH
    if not _GLOB_CHARS.match(pattern):
        return ("expected a glob of tool-name characters with * ? [...] {a,b}, like mcp__*__create*. These lists "
                "take globs, not regexes.")
    if globs.expand_braces(pattern) is None:
        return "the {a,b} groups expand to more than %d names." % globs.MAX_EXPANSIONS
    return None


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            for s in _strings(v):
                yield s
    elif isinstance(obj, list):
        for v in obj:
            for s in _strings(v):
                yield s


def read_json(path):
    """A config file's JSON, or None when it is missing. A folder, device, FIFO or oversized file is an error."""
    try:
        text = ledger.read_regular(path, CONFIG_MAX_BYTES)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise ConfigError("%s: can't be read (%s)." % (path, exc.strerror or exc))
    except ValueError:
        raise ConfigError("%s: not valid UTF-8 text." % path)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ConfigError("%s: not valid JSON (%s)." % (path, exc))
    except RecursionError:
        raise ConfigError("%s: not valid JSON (nested too deeply)." % path)


def user_config_path(data_dir):
    return os.path.join(data_dir, "config.json") if data_dir else None


def project_config_path(project_dir):
    return os.path.join(project_dir, ".checkrein", "config.json") if project_dir else None


def _env_layer():
    layer = {}
    preset = os.environ.get("CLAUDE_PLUGIN_OPTION_PRESET", "").strip()
    if preset:
        layer["preset"] = preset
    fail_mode = os.environ.get("CLAUDE_PLUGIN_OPTION_FAIL_MODE", "").strip()
    if fail_mode:
        layer["fail_mode"] = fail_mode
    scanner = os.environ.get("CLAUDE_PLUGIN_OPTION_SCANNER_COMMAND", "").strip()
    if scanner:
        try:
            layer["scanner"] = {"command": shlex.split(scanner)}
        except ValueError:
            raise ConfigError("Plugin option scanner_command: could not split %r into words." % scanner)
    return layer


def _preset_levels(registry, preset):
    return {rid: spec["presets"][preset] for rid, spec in registry["rules"].items()}


class Effective(object):
    """The resolved config, where each value came from, and what was ignored."""

    def __init__(self):
        self.values = {}
        self.sources = {}
        self.notes = []
        self.pending_approval = []
        self.project_error = None  # The validation message, for doctor only: it may quote values from the file.

    def level(self, rule_id):
        return self.values["rules"].get(rule_id, "off")

    def get(self, key, default=None):
        return self.values.get(key, default)


def resolve(data_dir=None, project_dir=None, registry=None):
    registry = registry or load_registry()
    eff = Effective()
    defaults = registry["defaults"]
    eff.values = {
        "preset": "standard",
        "fail_mode": "ask",
        "rules": _preset_levels(registry, "standard"),
        "protected_branches": list(defaults["protected_branches"]),
        "extra_skill_roots": [],
        "extra_installers": list(defaults["installers"]),
        "mcp_write_tools": list(defaults["mcp_write_tools"]),
        "secret_ignore_paths": [],
        "mcp_routine": [],
        "scanner": None,
        "secret_scanner": "auto",
    }
    for key in eff.values:
        eff.sources[key] = "default"
    eff.sources["rules"] = {rid: "default" for rid in eff.values["rules"]}

    env_layer = validate(_env_layer(), "plugin options", registry)
    user_path = user_config_path(data_dir)
    user_file = read_json(user_path) if user_path else None
    if user_file is not None:
        validate(user_file, user_path, registry)
    _apply_user(eff, env_layer, "plugin options", registry)
    if user_file:
        _apply_user(eff, user_file, "user config", registry)

    proj_path = project_config_path(project_dir)
    try:
        proj_file = read_json(proj_path) if proj_path else None
        if proj_file is not None:
            validate(proj_file, proj_path, registry)
    except ConfigError as exc:
        # A project file can only tighten, so a broken one must not hand the call to fail_mode (which may be
        # looser than the rules). It is skipped whole; the user layer and defaults still apply.
        eff.project_error = str(exc)
        eff.notes.append(PROJECT_IGNORED_NOTE)
        return eff
    if proj_file is not None:
        _apply_project(eff, proj_file, project_dir, data_dir, registry)
    return eff


def _apply_user(eff, layer, label, registry):
    if "preset" in layer:
        eff.values["preset"] = layer["preset"]
        eff.sources["preset"] = label
        for rid, level in _preset_levels(registry, layer["preset"]).items():
            eff.values["rules"][rid] = level
            eff.sources["rules"][rid] = "%s (preset %s)" % (label, layer["preset"])
    for key, value in layer.items():
        if key in ("version", "preset"):
            continue
        if key == "rules":
            for rid, level in value.items():
                eff.values["rules"][rid] = level
                eff.sources["rules"][rid] = label
        elif SCHEMA[key][1] == "safety-union":
            eff.values[key] = sorted(set(eff.values[key]) | set(value))
            eff.sources[key] = label
        else:
            eff.values[key] = value
            eff.sources[key] = label


def _apply_project(eff, layer, project_dir, data_dir, registry):
    label = "project config"
    rules = registry["rules"]
    proposed = {}
    if "preset" in layer:
        for rid, level in _preset_levels(registry, layer["preset"]).items():
            proposed[rid] = level
    proposed.update(layer.get("rules", {}))
    for rid, level in proposed.items():
        levels = rules[rid]["levels"]
        current = eff.values["rules"][rid]
        if _order(levels, level) > _order(levels, current):
            eff.values["rules"][rid] = level
            eff.sources["rules"][rid] = label
        elif _order(levels, level) < _order(levels, current) and rid in layer.get("rules", {}):
            eff.notes.append("Ignored: the project config asks for %s at %r, looser than your %r. "
                             "Only your own config can loosen a rule." % (rid, level, current))
    if "fail_mode" in layer:
        if _order(FAIL_MODES, layer["fail_mode"]) > _order(FAIL_MODES, eff.values["fail_mode"]):
            eff.values["fail_mode"] = layer["fail_mode"]
            eff.sources["fail_mode"] = label
        elif layer["fail_mode"] != eff.values["fail_mode"]:
            eff.notes.append("Ignored: the project config asks for fail_mode %r, looser than %r."
                             % (layer["fail_mode"], eff.values["fail_mode"]))
    for key, value in layer.items():
        cls = SCHEMA[key][1]
        if cls == "safety-union":
            eff.values[key] = sorted(set(eff.values[key]) | set(value))
            eff.sources[key] = "%s + %s" % (eff.sources[key], label)
        elif cls == "loosen-user":
            eff.notes.append("Ignored: %s in the project config. Only your own config can set it." % key)
        elif cls in ("loosen-approved", "exec"):
            if approve.is_approved(data_dir, project_dir, key, value):
                if cls == "loosen-approved":
                    eff.values[key] = sorted(set(eff.values[key]) | set(value))
                else:
                    eff.values[key] = value
                eff.sources[key] = "%s (approved)" % label
            else:
                eff.pending_approval.append(key)
                eff.notes.append("Not applied: %s in the project config waits for your approval "
                                 "(/checkrein:config approve %s)." % (key, key))
        elif cls == "preference":
            eff.values[key] = value
            eff.sources[key] = label


def write_layer(path, data, registry=None):
    """Validate and write a config layer atomically. Returns the old content."""
    registry = registry or load_registry()
    data.setdefault("version", SUPPORTED_VERSION)
    validate(data, path, registry)
    old = read_json(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ledger.write_json_atomic(path, data)
    return old

"""The install gate: fetch into quarantine, run static checks and an optional
third-party scanner, and give a verdict.

Verdicts:
- PASS: a scanner ran and reported nothing, and no static finding is medium or high.
- REVIEW: anything medium, or no scanner ran. Installing needs an override.
- BLOCK: any high finding. Installing needs an override.
"""

import json
import os
import re
import shutil
import subprocess
import time
import uuid

from . import ledger
from . import secrets

SEVERITIES = ("info", "low", "medium", "high")
TEXT_LIMIT = 1024 * 1024
BINARY_MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"MZ")
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".otf", ".pdf", ".mp3", ".mp4"}
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".php", ".go"}

_INVISIBLE = re.compile(u"[\u200b\u200c\u200d\u2060-\u2064\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")
# Credential reads are matched only under a home-folder path: a project's own dotfiles are not credentials. The
# names below are folders and files that hold keys and tokens; the regex adds the home prefix and the leading dot.
_HOME = (r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|/Users/[\w.-]+|/home/[\w.-]+)[/\\]"
         r"|expanduser\(\s*['\"]~['\"]\s*\)\s*,\s*['\"]|Path\.home\(\)\s*/\s*['\"]")
_CREDENTIAL_HOME_NAMES = ("ssh", "aws", "azure", "gnupg", "kube", "docker", "config/gcloud", "config/gh", "netrc",
                          "git-credentials", "npmrc", "pypirc")
# Browser password and cookie stores, and the macOS command that prints a saved password, are named directly.
_CRED_RX = re.compile(r"(?i)(?:%s)\.(?:%s)\b|\bsecurity\s+find-(?:generic|internet)-password"
                      r"|\bLogin Data\b|Cookies\.binarycookies|\bkey4\.db\b"
                      % (_HOME, "|".join(re.escape(n) for n in _CREDENTIAL_HOME_NAMES)))
_HOME_DOT_RX = re.compile(r"(?:%s)(?:\.(?!claude\b)[\w-]|Library/)" % _HOME)
_LINE_CHECKS = [
    ("S-PIPE-SHELL", "high", "downloads code and pipes it into a shell or interpreter",
     re.compile(r"(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl|ruby|iex)\b")),
    ("S-CRED-READ", "high", "reaches into a credential folder or file in your home folder, or asks the OS for a saved "
                            "password", _CRED_RX),
    ("S-HOME-READ", "medium", "reads hidden files or app data in your home folder", _HOME_DOT_RX),
    ("S-PERSIST", "high", "writes to shell startup files, launch agents, cron, git hooks or Claude settings",
     re.compile(r"(?i)(>>?\s*~?/?[\w./]*\.(zshrc|bashrc|bash_profile|profile|zprofile)\b|LaunchAgents|LaunchDaemons|crontab\s+-"
                r"|\.git/hooks/[\w.-]+|\bgit\b[^\n]*\bconfig\b[^\n]*core\.hooksPath|core\.hooksPath\s*="
                r"|\.claude/settings(\.local)?\.json)")),
    ("S-BYPASS", "high", "turns off permission prompts or safety checks",
     re.compile(r"(?i)(--dangerously-skip-permissions|dangerously[-_]?skip[-_]?permissions[\"']?\s*[:=]\s*true"
                r"|--permission-mode[\s=]+[\"']?bypassPermissions|defaultMode[\"']?\s*[:=]\s*[\"']?bypassPermissions"
                r"|disableAllHooks[\"']?\s*[:=]\s*true|\b(commit|push|merge|rebase|am|cherry-pick)\b[^\n]{0,80}--no-verify"
                r"|disable(_|-|\s)?(all\s+)?(hooks|sandbox|guard))")),
    ("S-INJECTION", "medium", "text that tries to steer the agent (ignore instructions, hide from the user)",
     re.compile(r"(?i)(ignore (all |any )?(previous|prior|above|earlier) (instructions|rules)|disregard (the |your |all )?(system|previous|prior)"
                r"|do not (tell|inform|mention (this )?to|alert) the user|without (asking|telling|informing) the user|you are now (in )?"
                r"|this is (an? )?(authorized|sanctioned) (test|request)|(system|developer) (prompt|message) override)")),
    ("S-NETWORK", "medium", "makes network calls",
     re.compile(r"(?i)(\bcurl\b|\bwget\b|requests\.(get|post|put)|urllib\.request|http\.client|\bfetch\(|axios\.|XMLHttpRequest|net/http|socket\.connect|\bnc\s+-)")),
    ("S-OBFUSCATION", "medium", "decodes or evaluates hidden code",
     re.compile(r"(?i)(base64\s+(-d|--decode)|b64decode|atob\(|fromCharCode\(|\beval\s*\(|exec\s*\(\s*(compile|base64|bytes)|marshal\.loads)")),
    ("S-BLOB", "medium", "contains a long encoded blob",
     re.compile(r"[A-Za-z0-9+/=]{300,}")),
]


# A guard or scanner names what it looks for inside its own regex patterns. A match that sits wholly inside a raw
# string literal written in regex syntax, on a line that holds nothing but such literals, is reported as low.
_RAW_LITERAL = re.compile(r"[rR]([\"'])((?:\\.|(?!\1)[^\\])*)\1")
_ANY_LITERAL = re.compile(r"[rRbBuU]?([\"'])(?:\\.|(?!\1)[^\\])*\1")
_REGEX_SYNTAX = re.compile(r"\\[sSbBwWdD]|\(\?|\[\^|\)[?*+]")
_PATTERN_LINE_REST = re.compile(r"^[\s(),%+]*(?:re\.compile\(|[A-Za-z_][\w.]*\s*=\s*(?:re\.compile\()?)?[\s(),%+]*$")


def _regex_literal_spans(line):
    """Spans of regex-syntax raw strings, when the line is only a pattern definition; else an empty list."""
    if not _PATTERN_LINE_REST.match(_ANY_LITERAL.sub("", line)):
        return []
    return [m.span(2) for m in _RAW_LITERAL.finditer(line) if _REGEX_SYNTAX.search(m.group(2))]


class Finding(object):
    def __init__(self, rule, severity, path, line, message):
        self.rule = rule
        self.severity = severity
        self.path = path
        self.line = line
        self.message = message

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity, "path": self.path, "line": self.line,
                "message": self.message}


def quarantine_dir(data_dir):
    return os.path.join(data_dir, "quarantine")


# Child processes (git clone of an untrusted source, a third-party scanner) get only what they need to run, so
# tokens in the user's environment never reach them. The scanner config can name more variables.
BASE_ENV = ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE",
            "TERM", "SSH_AUTH_SOCK", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "no_proxy", "SYSTEMROOT", "COMSPEC", "PATHEXT")


def child_env(extra=()):
    return {name: os.environ[name] for name in tuple(BASE_ENV) + tuple(extra) if name in os.environ}


def _run(cmd, cwd=None, timeout=120):
    env = child_env()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, universal_newlines=True)


_GH_SHORT = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(/.+)?$")


def parse_source(source):
    """Return (kind, location, subpath). kind is 'local' or 'git'."""
    src = source.strip()
    if os.path.exists(os.path.expanduser(src)):
        return "local", os.path.abspath(os.path.expanduser(src)), ""
    sub = ""
    if "#" in src:
        src, sub = src.split("#", 1)
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/(?:tree|blob)/[^/]+/(.+)$", src)
    if m:
        return "git", "https://github.com/%s/%s.git" % (m.group(1), m.group(2)), m.group(3)
    if src.startswith(("http://", "git://")):
        raise ValueError("Unencrypted sources are refused; use https or ssh.")
    if src.startswith(("https://", "ssh://", "git@")):
        return "git", src, sub.strip("/")
    m = _GH_SHORT.match(src)
    if m:
        return "git", "https://github.com/%s/%s.git" % (m.group(1), m.group(2)), (m.group(3) or "").strip("/") or sub
    raise ValueError("Unknown source %r. Use a local folder, a git URL, or owner/repo[/path]." % source)


def fetch(source, data_dir):
    """Copy or clone a source into a new quarantine folder. Returns (qid, tree_dir, origin)."""
    kind, location, sub = parse_source(source)
    qid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    base = os.path.join(quarantine_dir(data_dir), qid)
    os.makedirs(base)
    origin = {"source": source, "kind": kind, "location": location, "subpath": sub, "commit": None}
    if kind == "local":
        tree = os.path.join(base, "tree")
        shutil.copytree(location, tree, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    else:
        clone = os.path.join(base, "clone")
        res = _run(["git", "-c", "protocol.file.allow=never", "-c", "core.symlinks=true", "clone", "--depth", "1",
                    "--no-tags", "--single-branch", "--", location, clone], timeout=300)
        if res.returncode != 0:
            shutil.rmtree(base, ignore_errors=True)
            raise RuntimeError("git clone failed: %s" % res.stderr.strip()[-500:])
        head = _run(["git", "-C", clone, "rev-parse", "HEAD"])
        origin["commit"] = head.stdout.strip() or None
        shutil.rmtree(os.path.join(clone, ".git"), ignore_errors=True)
        tree = os.path.join(base, "tree")
        src_dir = os.path.normpath(os.path.join(clone, sub)) if sub else clone
        if not src_dir.startswith(clone) or not os.path.isdir(src_dir):
            shutil.rmtree(base, ignore_errors=True)
            raise RuntimeError("Path %r not found in the repository." % sub)
        shutil.copytree(src_dir, tree, symlinks=True)
        shutil.rmtree(clone, ignore_errors=True)
    return qid, tree, origin


def detect_kind(tree):
    if os.path.exists(os.path.join(tree, ".claude-plugin", "marketplace.json")) and \
            not os.path.exists(os.path.join(tree, ".claude-plugin", "plugin.json")):
        return "marketplace"
    if os.path.exists(os.path.join(tree, ".claude-plugin", "plugin.json")):
        return "plugin"
    if os.path.exists(os.path.join(tree, "SKILL.md")):
        return "skill"
    skills = sorted(d for d in os.listdir(os.path.join(tree, "skills")) if
                    os.path.exists(os.path.join(tree, "skills", d, "SKILL.md"))) \
        if os.path.isdir(os.path.join(tree, "skills")) else []
    if skills:
        return "skill-collection"
    return "unknown"


def skill_name(tree):
    try:
        with open(os.path.join(tree, "SKILL.md"), encoding="utf-8", errors="replace") as fh:
            head = fh.read(4000)
    except OSError:
        return None
    m = re.search(r"(?m)^name:\s*[\"']?([A-Za-z0-9_.:-]+)", head)
    return m.group(1) if m else None


def plugin_meta(tree):
    for name in ("plugin.json", "marketplace.json"):
        path = os.path.join(tree, ".claude-plugin", name)
        try:
            with open(path) as fh:
                return name, json.load(fh)
        except (OSError, ValueError):
            continue
    return None, {}


def static_scan(tree):
    findings = []
    total = 0
    # Unlike the hash, the scan looks inside __pycache__ and node_modules too.
    for rel, full in ledger._walk(tree, skip_dirs={".git"}):
        if os.path.islink(full):
            target = os.readlink(full)
            resolved = os.path.normpath(os.path.join(os.path.dirname(full), target))
            if os.path.isabs(target) or not resolved.startswith(os.path.abspath(tree) + os.sep):
                findings.append(Finding("S-SYMLINK", "high", rel, 0, "symlink points outside the package"))
            else:
                findings.append(Finding("S-SYMLINK", "low", rel, 0, "symlink inside the package"))
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        total += st.st_size
        ext = os.path.splitext(rel)[1].lower()
        if ext in (".pyc", ".pyo") or "__pycache__" in rel.split(os.sep):
            findings.append(Finding("S-PYC", "high", rel, 0, "compiled Python ships with the package; it can run instead of the source"))
            continue
        with open(full, "rb") as fh:
            head = fh.read(8192)
        if head.startswith(BINARY_MAGIC):
            findings.append(Finding("S-BINARY", "high", rel, 0, "native executable"))
            continue
        if b"\0" in head:
            sev = "info" if ext in MEDIA_EXT else "medium"
            findings.append(Finding("S-BINARY", sev, rel, 0, "binary file"))
            continue
        if st.st_size > TEXT_LIMIT:
            findings.append(Finding("S-SIZE", "low", rel, 0, "large file (%d KB), not scanned" % (st.st_size // 1024)))
            continue
        try:
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            findings.append(Finding("S-BINARY", "medium", rel, 0, "not valid UTF-8 text"))
            continue
        findings.extend(_scan_text_file(rel, text, ext))
        if os.path.basename(rel) == "hooks.json" or (os.path.basename(rel) == "plugin.json" and '"hooks"' in text):
            findings.append(Finding("S-HOOKS", "medium", rel, 0, "defines hooks: code that runs on every matching event"))
        if os.path.basename(rel) == ".mcp.json" or (os.path.basename(rel) == "plugin.json" and '"mcpServers"' in text):
            findings.append(Finding("S-MCP", "medium", rel, 0, "starts MCP servers"))
        if os.path.basename(rel) == "SKILL.md" and re.search(r"(?m)^hooks:", text[:4000]):
            findings.append(Finding("S-HOOKS", "medium", rel, 0, "skill frontmatter defines hooks"))
        if (st.st_mode & 0o111) and ext not in SCRIPT_EXT and not text.startswith("#!"):
            findings.append(Finding("S-EXEC-BIT", "low", rel, 0, "executable bit on a non-script file"))
    if total > 20 * 1024 * 1024:
        findings.append(Finding("S-SIZE", "medium", ".", 0, "package is over 20 MB"))
    return findings


def _scan_text_file(rel, text, ext):
    found = []
    seen = set()
    for number, line in enumerate(text.splitlines(), 1):
        if _INVISIBLE.search(line) and ("S-INVISIBLE", number) not in seen:
            seen.add(("S-INVISIBLE", number))
            found.append(Finding("S-INVISIBLE", "high", rel, number, "invisible or direction-changing Unicode characters"))
        spans = _regex_literal_spans(line) if ext in SCRIPT_EXT else []
        for rule, sev, message, rx in _LINE_CHECKS:
            if rule == "S-NETWORK" and ext not in SCRIPT_EXT:
                continue
            if rule == "S-HOME-READ" and _CRED_RX.search(line):
                continue  # Already reported as the stronger S-CRED-READ.
            for m in rx.finditer(line):
                if any(a <= m.start() and m.end() <= b for a, b in spans):
                    key, level, text = (rule + "~pattern", rel), "low", message + " (named in a regex pattern)"
                else:
                    key, level, text = (rule, rel), sev, message
                if key not in seen:
                    seen.add(key)  # One finding per rule per file is enough to review.
                    found.append(Finding(rule, level, rel, number, text))
    for hit in secrets.scan_text(text, high_only=True):
        found.append(Finding("S-SECRET", "high", rel, hit.line, "contains what looks like a %s" % hit.label))
    return found


def run_scanner(command, tree, report_path, timeout=600, env_names=()):
    """Run a third-party scanner. Returns dict with status: clean, findings, error, unavailable."""
    if not command:
        return {"status": "none"}
    argv = [c.replace("{path}", tree).replace("{report}", report_path) for c in command]
    if not shutil.which(argv[0]):
        return {"status": "unavailable", "detail": "%s is not on PATH" % argv[0]}
    try:
        res = subprocess.run(argv, env=child_env(env_names), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=timeout, universal_newlines=True)
    except subprocess.TimeoutExpired:
        return {"status": "error", "detail": "timed out after %ds" % timeout}
    log = report_path + ".log"
    with open(log, "w") as fh:
        fh.write(secrets.mask(res.stdout[-200000:]))
        fh.write("\n--- stderr ---\n")
        fh.write(secrets.mask(res.stderr[-50000:]))
    status = "clean" if res.returncode == 0 else "findings"
    count = _count_report_findings(report_path)
    if count:
        status = "findings"
    return {"status": status, "exit_code": res.returncode, "report": report_path if os.path.exists(report_path) else None,
            "log": log, "findings": count}


def _count_report_findings(path):
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    for key in ("findings", "issues", "results", "vulnerabilities"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, list):
            return len(value)
    return None


def verdict(findings, scanner):
    sev = max([SEVERITIES.index(f.severity) for f in findings] or [0])
    if sev >= SEVERITIES.index("high") or scanner.get("status") == "findings":
        return "BLOCK" if sev >= SEVERITIES.index("high") else "REVIEW"
    if sev >= SEVERITIES.index("medium") or scanner.get("status") != "clean":
        return "REVIEW"
    return "PASS"


_SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def vet(source, data_dir, scanner_command=None, name=None, scanner_env=()):
    if name is not None and not _SAFE_NAME.match(name):
        # The name picks a folder under skills/ and names the install folder: one plain path part only.
        raise ValueError("--name must be a plain skill name (letters, digits, . _ -), got %r." % name)
    qid, tree, origin = fetch(source, data_dir)
    kind = detect_kind(tree)
    subject = tree
    if kind == "skill-collection":
        if not name:
            choices = sorted(d for d in os.listdir(os.path.join(tree, "skills"))
                             if os.path.exists(os.path.join(tree, "skills", d, "SKILL.md")))
            report = {"id": qid, "kind": kind, "choices": choices, "verdict": None,
                      "message": "This repository holds several skills. Run vet again with --name <skill>."}
            _save_report(data_dir, qid, report)
            return report
        subject = os.path.join(tree, "skills", name)
        if not os.path.isdir(subject):
            raise RuntimeError("No skill named %r in this repository." % name)
        kind = "skill"
    meta_file, meta = plugin_meta(tree)
    if kind == "skill":
        pkg_name = name or skill_name(subject) or os.path.basename(origin["location"].rstrip("/")).replace(".git", "")
    else:
        pkg_name = name or meta.get("name") or os.path.basename(origin["location"].rstrip("/")).replace(".git", "")
    scope = _install_scope(tree, meta) if kind == "marketplace" else ["."]
    findings, runs = [], []
    for index, rel in enumerate(scope):
        folder = os.path.normpath(os.path.join(subject, rel))
        for f in static_scan(folder):
            f.path = os.path.normpath(os.path.join(rel, f.path))
            findings.append(f)
        if rel == ".claude-plugin" and len(scope) > 1:
            continue  # The scanner reads each plugin folder; the manifest alone is covered by the static checks.
        report_path = os.path.join(quarantine_dir(data_dir), "%s.scanner%s.json" % (qid, "-%d" % index if index else ""))
        runs.append(run_scanner(scanner_command, folder, report_path, env_names=scanner_env))
    scanner = _combine_scanner_runs(runs)
    result = {
        "id": qid,
        "name": pkg_name,
        "kind": kind,
        "origin": origin,
        "subject": os.path.relpath(subject, os.path.join(quarantine_dir(data_dir), qid)),
        "tree_hash": ledger.tree_hash(subject),
        "files": sum(1 for _ in ledger._walk(subject)),
        "scanned": scope,
        "scanner": scanner,
        "findings": [f.as_dict() for f in sorted(findings, key=lambda f: -SEVERITIES.index(f.severity))],
        "verdict": verdict(findings, scanner),
        "vetted_at": ledger.now(),
    }
    if kind in ("plugin", "marketplace"):
        result.update(_marketplace_info(tree, meta_file, meta))
    _save_report(data_dir, qid, result)
    return result


_SCANNER_ORDER = ("findings", "error", "unavailable", "none", "clean")


def _combine_scanner_runs(runs):
    if len(runs) == 1:
        return runs[0]
    if not runs:
        return {"status": "none"}
    # The worst run speaks for all of them, so the report line names its detail or report file.
    worst = min(runs, key=lambda r: _SCANNER_ORDER.index(r.get("status", "error")))
    return dict(worst, runs=runs)


def _install_scope(tree, meta):
    """Folders Claude Code installs from a marketplace: its manifest folder and each relative plugin folder.

    Tests, docs and other files beside them never reach a user's machine, so they are not vetted. A plugin
    whose source is the repository root brings the whole tree into scope.
    """
    root = os.path.realpath(tree)
    scope = {".claude-plugin"}
    for p in (meta.get("plugins") if isinstance(meta, dict) else None) or []:
        src = p.get("source") if isinstance(p, dict) else None
        if not isinstance(src, str) or not src.startswith("."):
            continue
        folder = os.path.realpath(os.path.join(tree, src))
        if folder == root:
            return ["."]
        if folder.startswith(root + os.sep) and os.path.isdir(folder):
            scope.add(os.path.relpath(folder, root).replace(os.sep, "/"))
    return sorted(scope)

def _marketplace_info(tree, meta_file, meta):
    """Which plugins a vetted repository covers, and the hash of each plugin folder."""
    if meta_file == "marketplace.json":
        mdata = meta
    else:
        try:
            with open(os.path.join(tree, ".claude-plugin", "marketplace.json")) as fh:
                mdata = json.load(fh)
        except (OSError, ValueError):
            mdata = None
    if not isinstance(mdata, dict):
        return {"marketplace": None, "marketplace_plugins": [], "external_plugins": [], "plugin_hashes": {}}
    covered, external, hashes = [], [], {}
    root = os.path.realpath(tree)
    for p in mdata.get("plugins") or []:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        src = p.get("source")
        if isinstance(src, str) and (src.startswith("./") or src in (".", "./")):
            folder = os.path.realpath(os.path.join(tree, src))
            if folder == root or folder.startswith(root + os.sep):
                covered.append(p["name"])
                if os.path.isdir(folder):
                    hashes[p["name"]] = ledger.tree_hash(folder)
                continue
        external.append(p["name"])
    return {"marketplace": mdata.get("name"), "marketplace_plugins": covered, "external_plugins": external,
            "plugin_hashes": hashes}


def _save_report(data_dir, qid, report):
    with open(os.path.join(quarantine_dir(data_dir), qid + ".json"), "w") as fh:
        json.dump(report, fh, indent=2)


def load_report(data_dir, qid):
    if not re.match(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$", qid or ""):
        raise ValueError("Bad quarantine id %r." % qid)
    with open(os.path.join(quarantine_dir(data_dir), qid + ".json")) as fh:
        return json.load(fh)

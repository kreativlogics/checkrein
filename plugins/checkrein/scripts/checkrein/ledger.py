"""The install ledger: what was vetted, approved, and what it looked like.

Each entry records a tree hash. The drift check compares installed skills and
plugin caches against it. A cheap fingerprint (paths, sizes, mtimes) skips the
full hash when nothing has changed.

A missing ledger means "not set up yet". A ledger that can't be read is an
error: the install rules then deny every install until it is repaired.
"""

import contextlib
import errno
import hashlib
import json
import os
import re
import stat
import time

try:
    import fcntl
except ImportError:  # Windows: no advisory locks; writes stay atomic, concurrent updates are not serialised.
    fcntl = None

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".trash"}
SKIP_FILES = {".DS_Store"}
LEDGER_VERSION = 1
LEDGER_MAX_BYTES = 16 * 1024 * 1024


def read_regular(path, limit):
    """Text of a regular file of at most limit bytes.

    Raises FileNotFoundError when it is missing, and another OSError when it is a folder, a device, a FIFO or
    too large. The open never blocks (a FIFO would hang the hook), and a device is refused before it is opened.
    """
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise OSError(errno.EINVAL, "not a regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if st.st_size > limit:
            raise OSError(errno.EFBIG, "larger than %d bytes" % limit)
        chunks = []
        size = 0
        while size <= limit:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > limit:
            raise OSError(errno.EFBIG, "larger than %d bytes" % limit)
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8")


class LedgerError(Exception):
    pass


def ledger_path(data_dir):
    return os.path.join(data_dir, "ledger.json")


def load(data_dir):
    """Return the ledger dict, None if it doesn't exist, or raise LedgerError."""
    path = ledger_path(data_dir)
    try:
        data = json.loads(read_regular(path, LEDGER_MAX_BYTES))
    except FileNotFoundError:
        return None
    except (ValueError, OSError, RecursionError) as exc:
        raise LedgerError("The ledger at %s can't be read (%s)." % (path, exc))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        raise LedgerError("The ledger at %s has an unexpected shape." % path)
    if data.get("version", 1) > LEDGER_VERSION:
        raise LedgerError("The ledger was written by a newer checkrein. Update the plugin.")
    return data


def save(data_dir, data):
    os.makedirs(data_dir, exist_ok=True)
    data["version"] = LEDGER_VERSION
    write_json_atomic(ledger_path(data_dir), data)


def write_json_atomic(path, data):
    """Write JSON through a unique temp file in the same folder, then rename it over the target."""
    import tempfile  # Only writers need it; the hook's read path stays lean.

    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def locked(data_dir, name="ledger"):
    """Hold an exclusive lock on the data folder's <name>.lock for a load-modify-save. Not re-entrant."""
    if fcntl is None:
        yield
        return
    os.makedirs(data_dir, exist_ok=True)
    fd = os.open(os.path.join(data_dir, ".%s.lock" % name), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def empty():
    return {"version": LEDGER_VERSION, "entries": {}}


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _walk(root, skip_dirs=SKIP_DIRS):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs
                             and not os.path.islink(os.path.join(dirpath, d)))
        links = [d for d in os.listdir(dirpath) if os.path.islink(os.path.join(dirpath, d))
                 and os.path.isdir(os.path.join(dirpath, d))]
        for name in sorted(set(filenames) | set(links)):
            if name in SKIP_FILES:
                continue
            full = os.path.join(dirpath, name)
            yield os.path.relpath(full, root), full


def fingerprint(root):
    """Cheap change detector: paths, sizes, modes and mtimes."""
    h = hashlib.sha256()
    for rel, full in _walk(root):
        try:
            st = os.lstat(full)
        except OSError:
            continue
        h.update(("%s\0%d\0%o\0%d\n" % (rel, st.st_size, st.st_mode, st.st_mtime_ns)).encode("utf-8", "replace"))
    return h.hexdigest()


def tree_hash(root):
    """Content hash: relative paths, exec bits, file bytes, symlink targets."""
    h = hashlib.sha256()
    for rel, full in _walk(root):
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            h.update(("L\0%s\0%s\n" % (rel, os.readlink(full))).encode("utf-8", "replace"))
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        fh_hash = hashlib.sha256()
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                fh_hash.update(chunk)
        execbit = "x" if st.st_mode & 0o111 else "-"
        h.update(("F\0%s\0%s\0%s\n" % (rel, execbit, fh_hash.hexdigest())).encode("utf-8", "replace"))
    return h.hexdigest()


def _claude_dir(home):
    from .context import claude_dir  # Imported here: context loads the shell reader, which most callers skip.
    return claude_dir(home)


def skill_roots(home, project_dir, extra=()):
    roots = [("user", os.path.join(_claude_dir(home), "skills"))]
    if project_dir:
        roots.append(("project", os.path.join(project_dir, ".claude", "skills")))
    for path in extra:
        roots.append(("extra", os.path.expanduser(path)))
    return roots


# Bounds of the walk for skill folders nested in a project (packages/app/.claude/skills): folders deep, folders
# looked at, and folders never entered.
NESTED_DEPTH = 8
NESTED_LIMIT = 20000
NESTED_SKIP = {"node_modules", ".git", ".hg", ".svn", "__pycache__"}


def nested_skill_roots(project_dir):
    """.claude/skills folders below the project's own, found by a bounded walk of the project."""
    out = []
    if not project_dir or not os.path.isdir(project_dir):
        return out
    seen = 0
    top = os.path.join(project_dir, ".claude", "skills")
    queue = [(project_dir, 0)]
    while queue and seen < NESTED_LIMIT:
        folder, depth = queue.pop(0)
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        for name in names:
            path = os.path.join(folder, name)
            if name in NESTED_SKIP or os.path.islink(path) or not os.path.isdir(path):
                continue
            seen += 1
            if name == ".claude":
                skills = os.path.join(path, "skills")
                if skills != top and os.path.isdir(skills):
                    out.append(skills)
                continue
            if depth + 1 < NESTED_DEPTH:
                queue.append((path, depth + 1))
    return out


def plugin_cache_root(home):
    return os.path.join(_claude_dir(home), "plugins", "cache")


def inventory(home, project_dir, extra_roots=()):
    """Installed skills and cached plugins: {key: path}."""
    items = {}
    roots = skill_roots(home, project_dir, extra_roots) + [("nested", r) for r in nested_skill_roots(project_dir)]
    for scope, root in roots:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if name.startswith(".") or not os.path.isdir(path):
                continue
            if not os.path.exists(os.path.join(path, "SKILL.md")):
                continue
            key = "skill:%s:%s" % (scope, name) if scope in ("user", "project") else "skill:%s:%s" % (root, name)
            items[key] = path
    cache = plugin_cache_root(home)
    if os.path.isdir(cache):
        for market in sorted(os.listdir(cache)):
            mpath = os.path.join(cache, market)
            if market.startswith(".") or not os.path.isdir(mpath):
                continue
            for plugin in sorted(os.listdir(mpath)):
                ppath = os.path.join(mpath, plugin)
                if plugin.startswith(".") or not os.path.isdir(ppath):
                    continue
                for version in sorted(os.listdir(ppath)):
                    vpath = os.path.join(ppath, version)
                    if version.startswith(".") or not os.path.isdir(vpath):
                        continue
                    items["plugin:%s@%s#%s" % (plugin, market, version)] = vpath
    return items


_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_SCP_HOST = re.compile(r"^[^/:]+:(?!\d+(/|$))")


def normalize_source(source, cwd=None):
    """A comparable form of a marketplace or plugin source: local:<real path> or <host>/<path>[#ref].

    owner/repo, github.com/owner/repo, https://, ssh:// and git@host: forms of one repository give the same
    string; .git, a trailing slash, www. and the host's case don't matter. GitHub paths ignore case, as GitHub does.
    A different host, owner, repository, sub-path or ref gives a different string. A relative local path is read
    against cwd, the folder the command runs in.
    """
    src = (source or "").strip()
    if src[:7].lower() == "file://":
        # A file URL is a local folder: file:///a/b is /a/b, and file://host/a/b names a path on host, never a
        # GitHub repository.
        src = src[7:]
        if not src.startswith("/"):
            return "local-host:" + src
    expanded = os.path.join(cwd or os.getcwd(), os.path.expanduser(src))
    if src.startswith(("/", "./", "../", "~")) or os.path.isdir(expanded):
        return "local:" + os.path.realpath(expanded)
    src, hash_, ref = src.partition("#")
    # Unencrypted fetches can be tampered with on the way, so they never match an https or ssh record.
    insecure = "insecure:" if src.lower().startswith(("http://", "git://")) else ""
    src = _SCHEME.sub("", src)
    at = src.find("@")
    if at != -1 and "/" not in src[:at] and ":" not in src[:at]:
        src = src[at + 1:]  # A user name, as in git@host.
    if _SCP_HOST.match(src):
        src = src.replace(":", "/", 1)  # host:owner/repo, the scp-like form.
    first, _, rest = src.partition("/")
    if "." in first or ":" in first or first.lower() == "localhost":
        host, path = first.lower(), rest
    else:
        host, path = "github.com", src  # owner/repo shorthand.
    if host.startswith("www."):
        host = host[4:]
    path = path.strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    if host == "github.com":
        path = path.lower()
    return "%s%s/%s%s%s" % (insecure, host, path, hash_, ref)


def find_plugin_approval(entries, name, market=None):
    """The ledger entry that approves installing plugin name@market, or (None, None)."""
    for ekey, entry in sorted(entries.items()):
        kind = entry.get("kind")
        # A plugin approval names the marketplace it may come from; one without (older ledgers) covers none.
        if kind == "plugin" and entry.get("name") == name and entry.get("marketplace") \
                and (market is None or entry.get("marketplace") == market):
            return ekey, entry
        if kind == "marketplace" and name in (entry.get("plugins") or []) and (market is None or entry.get("name") == market):
            return ekey, entry
    return None, None


def find_marketplace_approval(entries, source, cwd=None):
    want = normalize_source(source, cwd)
    for ekey, entry in sorted(entries.items()):
        if entry.get("kind") not in ("marketplace", "plugin"):
            continue
        if want in [normalize_source(s) for s in entry.get("sources") or []]:
            return ekey, entry
    return None, None


def plugin_entry_for(entries, key):
    """Find the approval entry for an installed plugin cache key, and the hash it was vetted at."""
    base = key.split("#", 1)[0]  # plugin:name@market
    name, _, market = base[len("plugin:"):].partition("@")
    ekey, entry = find_plugin_approval(entries, name, market)
    if entry is None:
        return None, None, None
    expected = (entry.get("plugin_hashes") or {}).get(name) or entry.get("tree_hash")
    return ekey, entry, expected


def drift(data_dir, home, project_dir, extra_roots=(), bind=True):
    """Compare installed items with the ledger.

    Returns dict with lists: changed, unvetted, missing, bound, and ok count.
    Updates fingerprints (and binds first-seen plugin caches) when bind=True.
    """
    if bind:
        with locked(data_dir):
            return _drift(data_dir, home, project_dir, extra_roots, bind)
    return _drift(data_dir, home, project_dir, extra_roots, bind)


def _drift(data_dir, home, project_dir, extra_roots, bind):
    data = load(data_dir)
    if data is None:
        return None
    entries = data["entries"]
    report = {"changed": [], "unvetted": [], "missing": [], "bound": [], "ok": 0}
    dirty = False
    seen = set()
    for key, path in inventory(home, project_dir, extra_roots).items():
        if key.startswith("plugin:"):
            ekey, entry, expected = plugin_entry_for(entries, key)
            if entry is None:
                report["unvetted"].append(key)
                continue
            seen.add(ekey)
            caches = entry.setdefault("caches", {})
            known = caches.get(key)
            fp = fingerprint(path)
            if known and known.get("fingerprint") == fp:
                th = known.get("tree_hash")
            else:
                th = tree_hash(path)
            # The copy Claude Code downloaded differs from what was vetted: changed, every session until a new
            # vet and approval of that content.
            vetted = expected is None or th == expected
            if known is None:
                if bind:
                    caches[key] = {"tree_hash": th, "fingerprint": fp, "first_seen": now(), "matches_vetted": vetted}
                    dirty = True
                report["bound" if vetted else "changed"].append(key)
                continue
            if known.get("tree_hash") != th or not vetted:
                report["changed"].append(key)
            else:
                report["ok"] += 1
            if known.get("fingerprint") != fp and known.get("tree_hash") == th:
                known["fingerprint"] = fp
                dirty = True
            if known.get("matches_vetted") != vetted and known.get("tree_hash") == th:
                known["matches_vetted"] = vetted
                dirty = True
            continue
        entry = entries.get(key)
        if entry is None:
            report["unvetted"].append(key)
            continue
        seen.add(key)
        fp = fingerprint(path)
        if entry.get("fingerprint") == fp:
            report["ok"] += 1
            continue
        if tree_hash(path) == entry.get("tree_hash"):
            entry["fingerprint"] = fp
            dirty = True
            report["ok"] += 1
        else:
            report["changed"].append(key)
    for key, entry in entries.items():
        if key.startswith("skill:") and key not in seen:
            report["missing"].append(key)
    if dirty and bind:
        save(data_dir, data)
    return report

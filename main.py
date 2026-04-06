import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_PORT = 8080
HOME_ROOT = os.path.expanduser("~")
PROJECTS_ROOT = os.path.expanduser("~/projects")
SCAN_SESSION_TTL_SECONDS = 60 * 60
SCAN_SESSION_LIMIT = 24

RUNTIME = {"host": "localhost", "port": DEFAULT_PORT, "open_browser": True}
SCAN_SESSIONS = {}

EXCLUDED_DIR_NAMES = {
    ".git",
    ".svn",
    ".hg",
    ".Trash",
    "Applications",
    "System",
    "Volumes",
    "dev",
    "proc",
    "sys",
}

SCOPE_DEFINITIONS = {
    "projects": {
        "label": "Projects",
        "description": "Scan only ~/projects",
    },
    "home": {
        "label": "User home",
        "description": "Scan your home folder and user-level caches",
    },
    "full_mac": {
        "label": "Full Mac",
        "description": "Scan user homes plus system cache locations",
    },
}

TARGET_RULES = [
    {
        "key": "node_modules",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Node modules",
        "category": "Dependencies",
    },
    {
        "key": "__pycache__",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Python bytecode cache",
        "category": "Python",
    },
    {
        "key": ".pytest_cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Pytest cache",
        "category": "Python",
    },
    {
        "key": ".mypy_cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Mypy cache",
        "category": "Python",
    },
    {
        "key": ".ruff_cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Ruff cache",
        "category": "Python",
    },
    {
        "key": ".next",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Next.js build cache",
        "category": "Frontend",
    },
    {
        "key": ".nuxt",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Nuxt build cache",
        "category": "Frontend",
    },
    {
        "key": ".svelte-kit",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "SvelteKit cache",
        "category": "Frontend",
    },
    {
        "key": ".parcel-cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Parcel cache",
        "category": "Frontend",
    },
    {
        "key": ".angular",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Angular cache",
        "category": "Frontend",
    },
    {
        "key": ".cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Generic cache folder",
        "category": "Caches",
    },
    {
        "key": ".gradle",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Gradle cache",
        "category": "Build",
    },
    {
        "key": "target",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Maven/Rust target output",
        "category": "Build",
    },
    {
        "key": "build",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Build output",
        "category": "Build",
    },
    {
        "key": "dist",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Distribution output",
        "category": "Build",
    },
    {
        "key": "out",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Compiled output",
        "category": "Build",
    },
    {
        "key": "coverage",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Coverage report output",
        "category": "Testing",
    },
    {
        "key": ".tox",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Tox virtualenv cache",
        "category": "Testing",
    },
    {
        "key": ".terraform",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Terraform module cache",
        "category": "Infrastructure",
    },
    {
        "key": ".DS_Store",
        "kind": "file_exact",
        "modes": {"safe", "aggressive"},
        "label": "macOS Finder metadata",
        "category": "macOS",
    },
    {
        "key": ".pyc",
        "kind": "file_suffix",
        "modes": {"aggressive"},
        "label": "Python compiled file",
        "category": "Python",
    },
]

HOME_EXACT_RULES = [
    {
        "path_template": "{home}/Library/Caches",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "User app cache",
        "category": "System cache",
    },
    {
        "path_template": "{home}/Library/Caches/Google/Chrome",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Chrome browser cache",
        "category": "Browser cache",
    },
    {
        "path_template": "{home}/Library/Caches/com.microsoft.edgemac",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Edge browser cache",
        "category": "Browser cache",
    },
    {
        "path_template": "{home}/Library/Caches/BraveSoftware/Brave-Browser",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Brave browser cache",
        "category": "Browser cache",
    },
    {
        "path_template": "{home}/Library/Caches/Mozilla/Firefox",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Firefox browser cache",
        "category": "Browser cache",
    },
    {
        "path_template": "{home}/Library/Caches/com.apple.Safari",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Safari browser cache",
        "category": "Browser cache",
    },
    {
        "path_template": "{home}/Library/Logs",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "User logs",
        "category": "Logs",
    },
    {
        "path_template": "{home}/Library/Developer/Xcode/DerivedData",
        "strategy": "path",
        "modes": {"safe", "aggressive"},
        "label": "Xcode derived data",
        "category": "Developer tools",
    },
    {
        "path_template": "{home}/.Trash",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Trash items",
        "category": "macOS",
    },
    {
        "path_template": "{home}/.npm/_cacache",
        "strategy": "path",
        "modes": {"safe", "aggressive"},
        "label": "npm cache",
        "category": "Package manager cache",
    },
    {
        "path_template": "{home}/.pnpm-store",
        "strategy": "path",
        "modes": {"safe", "aggressive"},
        "label": "pnpm store cache",
        "category": "Package manager cache",
    },
    {
        "path_template": "{home}/.yarn/cache",
        "strategy": "path",
        "modes": {"safe", "aggressive"},
        "label": "Yarn cache",
        "category": "Package manager cache",
    },
    {
        "path_template": "{home}/.cache/pip",
        "strategy": "path",
        "modes": {"safe", "aggressive"},
        "label": "pip cache",
        "category": "Package manager cache",
    },
    {
        "path_template": "{home}/.m2/repository",
        "strategy": "path",
        "modes": {"safe", "aggressive"},
        "label": "Maven local repository cache",
        "category": "Package manager cache",
    },
]

SYSTEM_EXACT_RULES = [
    {
        "path_template": "/Library/Caches",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "System cache",
        "category": "System cache",
    },
    {
        "path_template": "/private/var/folders",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "macOS temp cache",
        "category": "System cache",
    },
    {
        "path_template": "/Library/Logs",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "System logs",
        "category": "Logs",
    },
    {
        "path_template": "/private/var/log",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "System temp logs",
        "category": "Logs",
    },
    {
        "path_template": "/opt/homebrew/var/cache",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Homebrew cache",
        "category": "Package manager cache",
    },
    {
        "path_template": "/usr/local/var/cache",
        "strategy": "children",
        "modes": {"safe", "aggressive"},
        "label": "Local cache",
        "category": "Package manager cache",
    },
]


def parse_args():
    parser = argparse.ArgumentParser(description="MacClean cleanup server")
    parser.add_argument("--host", default="localhost", help="HTTP bind host")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="HTTP bind port")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not auto-open browser on startup",
    )
    return parser.parse_args()


def is_admin_user():
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def admin_run_command(host, port):
    uv_bin = shutil.which("uv") or "uv"
    return f"sudo -E {uv_bin} run python main.py --host {host} --port {port}"


def normalize_mode(mode):
    return "aggressive" if mode == "aggressive" else "safe"


def normalize_scope(scope):
    return scope if scope in SCOPE_DEFINITIONS else "projects"


def rules_for_mode(mode):
    active = [rule for rule in TARGET_RULES if mode in rule["modes"]]
    return {
        "dirs": {rule["key"]: rule for rule in active if rule["kind"] == "dir"},
        "file_exact": {
            rule["key"]: rule for rule in active if rule["kind"] == "file_exact"
        },
        "file_suffix": [rule for rule in active if rule["kind"] == "file_suffix"],
    }


def path_is_within(path, root):
    try:
        path_real = os.path.realpath(path)
        root_real = os.path.realpath(root)
        return os.path.commonpath([path_real, root_real]) == root_real
    except ValueError:
        return False


def unique_existing_paths(paths):
    seen = set()
    result = []
    for path in paths:
        if not path:
            continue
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        if os.path.exists(path):
            result.append(path)
    return result


def discover_user_homes():
    homes = []
    if os.path.isdir("/Users"):
        for entry in os.listdir("/Users"):
            if entry in {"Shared", ".localized"}:
                continue
            path = os.path.join("/Users", entry)
            if os.path.isdir(path):
                homes.append(path)
    if os.path.isdir(HOME_ROOT):
        home_real = os.path.realpath(HOME_ROOT)
        if all(os.path.realpath(path) != home_real for path in homes):
            homes.append(HOME_ROOT)
    return unique_existing_paths(homes)


def system_roots_for_scope():
    if sys.platform != "darwin":
        return []
    return ["/Library", "/opt/homebrew", "/usr/local"]


def scope_roots(scope):
    scope = normalize_scope(scope)
    if scope == "projects":
        roots = [PROJECTS_ROOT]
    elif scope == "home":
        roots = [HOME_ROOT]
    else:
        roots = discover_user_homes() + system_roots_for_scope()
    extra_roots = os.environ.get("MACCLEAN_EXTRA_SCAN_ROOTS", "")
    if extra_roots.strip():
        roots.extend([part.strip() for part in extra_roots.split(",") if part.strip()])
    return unique_existing_paths(roots)


def homes_for_scope(scope):
    if normalize_scope(scope) == "full_mac":
        homes = discover_user_homes()
        return homes if homes else [HOME_ROOT]
    return [HOME_ROOT]


TARGET_RULES = [
    {
        "key": "node_modules",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Node modules",
        "category": "Dependencies",
    },
    {
        "key": "__pycache__",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Python bytecode cache",
        "category": "Python",
    },
    {
        "key": ".pytest_cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Pytest cache",
        "category": "Python",
    },
    {
        "key": ".mypy_cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Mypy cache",
        "category": "Python",
    },
    {
        "key": ".ruff_cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Ruff cache",
        "category": "Python",
    },
    {
        "key": ".next",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Next.js build cache",
        "category": "Frontend",
    },
    {
        "key": ".nuxt",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Nuxt build cache",
        "category": "Frontend",
    },
    {
        "key": ".svelte-kit",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "SvelteKit cache",
        "category": "Frontend",
    },
    {
        "key": ".parcel-cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Parcel cache",
        "category": "Frontend",
    },
    {
        "key": ".angular",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Angular cache",
        "category": "Frontend",
    },
    {
        "key": ".cache",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Generic cache folder",
        "category": "Caches",
    },
    {
        "key": ".gradle",
        "kind": "dir",
        "modes": {"safe", "aggressive"},
        "label": "Gradle cache",
        "category": "Build",
    },
    {
        "key": "build",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Build output",
        "category": "Build",
    },
    {
        "key": "dist",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Distribution output",
        "category": "Build",
    },
    {
        "key": "out",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Compiled output",
        "category": "Build",
    },
    {
        "key": "target",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Rust/Java target output",
        "category": "Build",
    },
    {
        "key": "coverage",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Coverage report output",
        "category": "Testing",
    },
    {
        "key": ".tox",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Tox virtualenv cache",
        "category": "Testing",
    },
    {
        "key": ".terraform",
        "kind": "dir",
        "modes": {"aggressive"},
        "label": "Terraform module cache",
        "category": "Infrastructure",
    },
    {
        "key": ".DS_Store",
        "kind": "file_exact",
        "modes": {"safe", "aggressive"},
        "label": "macOS Finder metadata",
        "category": "macOS",
    },
    {
        "key": ".pyc",
        "kind": "file_suffix",
        "modes": {"aggressive"},
        "label": "Python compiled file",
        "category": "Python",
    },
]


def rules_for_mode(mode):
    active = [rule for rule in TARGET_RULES if mode in rule["modes"]]
    return {
        "dirs": {rule["key"]: rule for rule in active if rule["kind"] == "dir"},
        "file_exact": {
            rule["key"]: rule for rule in active if rule["kind"] == "file_exact"
        },
        "file_suffix": [rule for rule in active if rule["kind"] == "file_suffix"],
    }


def is_safe_path(path):
    try:
        root_real = os.path.realpath(SEARCH_ROOT)
        path_real = os.path.realpath(path)
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        return False

def get_size(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            output = subprocess.check_output(["du", "-sk", path], text=True)
            return int(output.split()[0]) * 1024
        return os.path.getsize(path)
    except (subprocess.SubprocessError, OSError, ValueError, IndexError):
        return 0


def human_size(value):
    size = float(value)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def path_group(path):
    normalized = os.path.realpath(path)
    parts = normalized.split(os.sep)
    if len(parts) > 2 and parts[1] in {"Users", "home"}:
        return os.path.join(os.sep, parts[1], parts[2])
    if len(parts) > 1:
        return os.path.join(os.sep, parts[1])
    return normalized


def protected_delete_paths():
    protected = {
        "/",
        "/Users",
        "/Library",
        "/System",
        "/Applications",
        "/Volumes",
        "/private",
        HOME_ROOT,
        os.path.join(HOME_ROOT, "Library"),
        os.path.join(HOME_ROOT, "Library", "Caches"),
        os.path.join(HOME_ROOT, "Library", "Logs"),
        PROJECTS_ROOT,
    }
    return {os.path.realpath(path) for path in protected if path}


def is_protected_delete_path(path):
    return os.path.realpath(path) in protected_delete_paths()


def collect_children(path):
    try:
        names = os.listdir(path)
    except OSError:
        return []
    candidates = []
    for name in names:
        if name in {".", ".."}:
            continue
        candidates.append(os.path.join(path, name))
    return candidates


def classify_exact_rule(path, home_roots):
    for home in home_roots:
        for rule in HOME_EXACT_RULES:
            base = rule["path_template"].format(home=home)
            if path_is_within(path, base):
                return rule["label"], rule["category"]
    for rule in SYSTEM_EXACT_RULES:
        base = rule["path_template"]
        if path_is_within(path, base):
            return rule["label"], rule["category"]
    return "Known cache path", "Caches"


def exact_candidates(scope, mode):
    mode = normalize_mode(mode)
    scope = normalize_scope(scope)

    candidates = []
    seen = set()

    def add_candidate(path, label, category):
        if not path or not os.path.exists(path):
            return
        real = os.path.realpath(path)
        if real in seen:
            return
        seen.add(real)
        candidates.append({"path": path, "label": label, "category": category})

    for home in homes_for_scope(scope):
        for rule in HOME_EXACT_RULES:
            if mode not in rule["modes"]:
                continue
            base = rule["path_template"].format(home=home)
            if rule["strategy"] == "path":
                add_candidate(base, rule["label"], rule["category"])
            elif rule["strategy"] == "children":
                for child in collect_children(base):
                    add_candidate(child, rule["label"], rule["category"])

    if scope == "full_mac":
        for rule in SYSTEM_EXACT_RULES:
            if mode not in rule["modes"]:
                continue
            base = rule["path_template"]
            if rule["strategy"] == "path":
                add_candidate(base, rule["label"], rule["category"])
            elif rule["strategy"] == "children":
                for child in collect_children(base):
                    add_candidate(child, rule["label"], rule["category"])

    return candidates


def prune_scan_sessions():
    now = time.time()
    expired = [
        key
        for key, session in SCAN_SESSIONS.items()
        if now - session["created_at"] > SCAN_SESSION_TTL_SECONDS
    ]
    for key in expired:
        SCAN_SESSIONS.pop(key, None)

    if len(SCAN_SESSIONS) <= SCAN_SESSION_LIMIT:
        return

    ordered = sorted(
        SCAN_SESSIONS.items(),
        key=lambda entry: entry[1]["created_at"],
    )
    for key, _ in ordered[: len(SCAN_SESSIONS) - SCAN_SESSION_LIMIT]:
        SCAN_SESSIONS.pop(key, None)


def persist_scan_session(scan_id, allowed_paths, scope):
    prune_scan_sessions()
    SCAN_SESSIONS[scan_id] = {
        "created_at": time.time(),
        "scope": normalize_scope(scope),
        "paths": set(allowed_paths),
    }


def scan_stream(handler, mode="safe", scope="projects"):
    mode = normalize_mode(mode)
    scope = normalize_scope(scope)
    target_index = rules_for_mode(mode)
    scan_id = uuid.uuid4().hex

    total = 0
    count = 0
    permission_denied = 0
    seen = set()
    allowed_paths = set()
    roots = scope_roots(scope)
    rule_homes = homes_for_scope(scope) if scope in {"home", "full_mac"} else []
    client_connected = True

    def send(data):
        nonlocal client_connected
        if not client_connected:
            return False
        try:
            handler.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
            handler.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError):
            client_connected = False
            return False

    def emit_item(path, label, category):
        nonlocal total, count
        if not os.path.exists(path):
            return
        if is_protected_delete_path(path):
            return
        real = os.path.realpath(path)
        if real in seen:
            return
        seen.add(real)
        size = get_size(path)
        total += size
        count += 1
        allowed_paths.add(real)
        send(
            {
                "type": "item",
                "path": path,
                "size": size,
                "human": human_size(size),
                "project": path_group(path),
                "category": category,
                "label": label,
            }
        )

    send(
        {
            "type": "start",
            "mode": mode,
            "scope": scope,
            "is_admin": is_admin_user(),
            "roots": roots,
        }
    )

    for candidate in exact_candidates(scope, mode):
        if not client_connected:
            break
        emit_item(candidate["path"], candidate["label"], candidate["category"])

    for root in roots:
        if not client_connected or not os.path.isdir(root):
            continue

        def on_walk_error(err):
            nonlocal permission_denied
            errno = getattr(err, "errno", None)
            if isinstance(err, PermissionError) or errno in {1, 13}:
                permission_denied += 1

        for walk_root, dirs, files in os.walk(root, topdown=True, onerror=on_walk_error):
            if not client_connected:
                break

            pruned_dirs = []
            for directory in dirs:
                if directory in EXCLUDED_DIR_NAMES:
                    continue
                candidate_path = os.path.join(walk_root, directory)
                if os.path.islink(candidate_path):
                    continue
                pruned_dirs.append(directory)
            dirs[:] = pruned_dirs

            matched_dirs = []
            for directory in dirs:
                rule = target_index["dirs"].get(directory)
                if not rule:
                    continue
                path = os.path.join(walk_root, directory)
                if scope in {"home", "full_mac"}:
                    exact_label, exact_category = classify_exact_rule(path, rule_homes)
                    emit_item(path, exact_label, exact_category)
                else:
                    emit_item(path, rule["label"], rule["category"])
                matched_dirs.append(directory)

            if matched_dirs:
                dirs[:] = [directory for directory in dirs if directory not in matched_dirs]

            for file_name in files:
                rule = target_index["file_exact"].get(file_name)
                if not rule:
                    for suffix_rule in target_index["file_suffix"]:
                        if file_name.endswith(suffix_rule["key"]):
                            rule = suffix_rule
                            break

                if not rule:
                    continue

                path = os.path.join(walk_root, file_name)
                emit_item(path, rule["label"], rule["category"])

    persist_scan_session(scan_id, allowed_paths, scope)
    show_admin_hint = scope == "full_mac" and (not is_admin_user() or permission_denied > 0)
    send(
        {
            "type": "done",
            "mode": mode,
            "scope": scope,
            "total": human_size(total),
            "total_bytes": total,
            "count": count,
            "scan_id": scan_id,
            "permissions_denied": permission_denied,
            "is_admin": is_admin_user(),
            "admin_hint": (
                admin_run_command(RUNTIME["host"], RUNTIME["port"])
                if show_admin_hint
                else ""
            ),
        }
    )


def delete_paths(paths, scan_id):
    deleted_count = 0
    deleted_bytes = 0
    skipped = []
    invalid_scan_id = False

    prune_scan_sessions()
    session = SCAN_SESSIONS.get(scan_id or "")
    if not session:
        invalid_scan_id = True
        return {
            "deleted_count": 0,
            "deleted_bytes": 0,
            "deleted_human": human_size(0),
            "skipped": paths,
            "invalid_scan_id": invalid_scan_id,
        }

    allowed = session["paths"]

    for path in paths:
        if not path:
            skipped.append(path)
            continue
        real = os.path.realpath(path)
        if real not in allowed or is_protected_delete_path(path):
            skipped.append(path)
            continue
        if not os.path.exists(path):
            skipped.append(path)
            continue

        size = get_size(path)
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            deleted_count += 1
            deleted_bytes += size
            allowed.discard(real)
        except OSError:
            skipped.append(path)

    return {
        "deleted_count": deleted_count,
        "deleted_bytes": deleted_bytes,
        "deleted_human": human_size(deleted_bytes),
        "skipped": skipped,
        "invalid_scan_id": invalid_scan_id,
    }


def status_payload():
    return {
        "status": "ok",
        "platform": sys.platform,
        "current_user": getpass.getuser(),
        "is_admin": is_admin_user(),
        "projects_root": PROJECTS_ROOT,
        "home_root": HOME_ROOT,
        "scope_definitions": SCOPE_DEFINITIONS,
        "admin_command": admin_run_command(RUNTIME["host"], RUNTIME["port"]),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/":
            with open("ui/index.html", encoding="utf-8") as handle:
                self.respond(handle.read(), "text/html")
            return

        if parsed.path == "/stream":
            params = urllib.parse.parse_qs(parsed.query)
            mode = params.get("mode", ["safe"])[0]
            scope = params.get("scope", ["projects"])[0]

            self.send_response(200)
            self.send_header("Content-type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            scan_stream(self, mode=mode, scope=scope)
            return

        if parsed.path == "/targets":
            self.respond(json.dumps(TARGET_RULES), "application/json")
            return

        if parsed.path == "/status":
            self.respond(json.dumps(status_payload()), "application/json")
            return

        self.send_error(404)

    def do_POST(self):
        if self.path == "/delete":
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or "{}")
            result = delete_paths(body.get("paths", []), body.get("scan_id"))
            self.respond(json.dumps({"status": "ok", **result}), "application/json")
            return

        self.send_error(404)

    def respond(self, data, content_type):
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(data.encode())


def start(host, port, open_browser=True):
    RUNTIME["host"] = host
    RUNTIME["port"] = port
    RUNTIME["open_browser"] = open_browser
    server = HTTPServer((host, port), Handler)
    print(f"http://{host}:{port}")
    if open_browser:
        threading.Timer(1, lambda: webbrowser.open(f"http://{host}:{port}")).start()
    server.serve_forever()


if __name__ == "__main__":
    args = parse_args()
    start(args.host, args.port, open_browser=not args.no_browser)

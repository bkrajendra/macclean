import os
import subprocess
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import webbrowser
import urllib.parse
import shutil

PORT = 8080
SEARCH_ROOT = os.path.expanduser("~/projects")

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

def human_size(b):
    for unit in ['B','KB','MB','GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

def project_root(path):
    rel = os.path.relpath(path, SEARCH_ROOT)
    if rel.startswith(".."):
        return path
    parts = rel.split(os.sep)
    if len(parts) <= 1:
        return SEARCH_ROOT
    return os.path.join(SEARCH_ROOT, parts[0])

def scan_stream(handler, mode="safe"):
    mode = "aggressive" if mode == "aggressive" else "safe"
    target_index = rules_for_mode(mode)

    total = 0
    count = 0

    def send(data):
        handler.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
        handler.wfile.flush()

    if not os.path.isdir(SEARCH_ROOT):
        send(
            {
                "type": "error",
                "message": f"Search root not found: {SEARCH_ROOT}",
            }
        )
        send({"type": "done", "total": human_size(0), "total_bytes": 0, "count": 0})
        return

    for root, dirs, files in os.walk(SEARCH_ROOT, topdown=True):
        dirs[:] = [d for d in dirs if d != ".git"]

        matched_dirs = []
        for directory in dirs:
            rule = target_index["dirs"].get(directory)
            if not rule:
                continue

            path = os.path.join(root, directory)
            size = get_size(path)
            total += size
            count += 1

            send(
                {
                    "type": "item",
                    "path": path,
                    "size": size,
                    "human": human_size(size),
                    "project": project_root(path),
                    "category": rule["category"],
                    "label": rule["label"],
                }
            )
            matched_dirs.append(directory)

        # Do not recurse into directories that will be deleted anyway.
        if matched_dirs:
            dirs[:] = [d for d in dirs if d not in matched_dirs]

        for file_name in files:
            rule = target_index["file_exact"].get(file_name)
            if not rule:
                for suffix_rule in target_index["file_suffix"]:
                    if file_name.endswith(suffix_rule["key"]):
                        rule = suffix_rule
                        break

            if not rule:
                continue

            path = os.path.join(root, file_name)
            size = get_size(path)
            total += size
            count += 1

            send(
                {
                    "type": "item",
                    "path": path,
                    "size": size,
                    "human": human_size(size),
                    "project": project_root(path),
                    "category": rule["category"],
                    "label": rule["label"],
                }
            )

    send({"type": "done", "total": human_size(total), "total_bytes": total, "count": count})

def delete_paths(paths):
    deleted_count = 0
    deleted_bytes = 0
    skipped = []

    for p in paths:
        if not p or not is_safe_path(p):
            skipped.append(p)
            continue
        if not os.path.exists(p):
            skipped.append(p)
            continue

        size = get_size(p)
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
            deleted_count += 1
            deleted_bytes += size
        except OSError:
            skipped.append(p)

    return {
        "deleted_count": deleted_count,
        "deleted_bytes": deleted_bytes,
        "deleted_human": human_size(deleted_bytes),
        "skipped": skipped,
    }

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/":
            with open("ui/index.html", encoding="utf-8") as f:
                self.respond(f.read(), "text/html")

        elif parsed.path == "/stream":
            params = urllib.parse.parse_qs(parsed.query)
            mode = params.get("mode", ["safe"])[0]

            self.send_response(200)
            self.send_header("Content-type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            scan_stream(self, mode)
        elif parsed.path == "/targets":
            self.respond(json.dumps(TARGET_RULES), "application/json")

    def do_POST(self):
        if self.path == "/delete":
            length = int(self.headers.get('Content-Length'))
            body = json.loads(self.rfile.read(length))
            result = delete_paths(body.get("paths", []))
            self.respond(json.dumps({"status": "ok", **result}), "application/json")

    def respond(self, data, content_type):
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(data.encode())

def start():
    server = HTTPServer(("localhost", PORT), Handler)
    print(f"http://localhost:{PORT}")
    threading.Timer(1, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
    server.serve_forever()

if __name__ == "__main__":
    start()

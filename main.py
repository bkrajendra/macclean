import os
import subprocess
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import webbrowser
import urllib.parse

PORT = 8080
SEARCH_ROOT = os.path.expanduser("~/projects")

def get_size(path):
    try:
        return int(subprocess.check_output(f'du -sk "{path}"', shell=True).split()[0]) * 1024
    except:
        return 0

def human_size(b):
    for unit in ['B','KB','MB','GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

def project_root(path):
    parts = path.split("/")
    return "/".join(parts[:4]) if len(parts) > 4 else path

def scan_stream(handler, mode="safe"):
    total = 0

    def send(data):
        handler.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
        handler.wfile.flush()

    for root, dirs, files in os.walk(SEARCH_ROOT):

        if ".git" in root:
            continue

        # SAFE MODE filters
        if mode == "safe":
            targets = ["node_modules", "__pycache__", ".angular"]
        else:
            targets = ["node_modules", "__pycache__", ".angular", "build", "dist", "target"]

        for d in dirs:
            if d in targets:
                path = os.path.join(root, d)
                size = get_size(path)
                total += size

                send({
                    "type": "item",
                    "path": path,
                    "size": size,
                    "human": human_size(size),
                    "project": project_root(path)
                })

    send({"type": "done", "total": human_size(total)})

def delete_paths(paths):
    for p in paths:
        subprocess.call(f'rm -rf "{p}"', shell=True)

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/":
            with open("ui/index.html") as f:
                self.respond(f.read(), "text/html")

        elif parsed.path == "/stream":
            params = urllib.parse.parse_qs(parsed.query)
            mode = params.get("mode", ["safe"])[0]

            self.send_response(200)
            self.send_header("Content-type", "text/event-stream")
            self.end_headers()

            scan_stream(self, mode)

    def do_POST(self):
        if self.path == "/delete":
            length = int(self.headers.get('Content-Length'))
            body = json.loads(self.rfile.read(length))
            delete_paths(body.get("paths", []))
            self.respond(json.dumps({"status": "ok"}), "application/json")

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

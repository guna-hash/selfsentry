"""Local production-build server with SPA navigation fallback."""

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = Path(self.translate_path(urlsplit(self.path).path))
        if not path.exists() and not Path(urlsplit(self.path).path).suffix:
            self.path = "/index.html"
        super().do_GET()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--port", type=int, default=5173)
    args = parser.parse_args()
    ThreadingHTTPServer(
        ("127.0.0.1", args.port), partial(Handler, directory=args.directory)
    ).serve_forever()

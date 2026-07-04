"""A deliberately-buggy mock API to validate the fuzzer's oracle."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _all(self):
        raw = ""
        if "content-length" in {k.lower() for k in self.headers.keys()}:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        blob = self.path + " " + raw
        # BUG 1: leaks a SQL error when a quote appears anywhere
        if "'" in blob:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"java.sql.SQLException: You have an error in your SQL syntax")
            return
        # BUG 2: reflects notes/firstName back unescaped
        if "<script>" in raw:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(("<html>" + raw + "</html>").encode())
            return
        # otherwise behave: reject obviously bad, accept the rest
        if "etc/passwd" in blob or "99999" in blob:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"bad request"}')
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    do_GET = _all
    do_POST = _all
    do_PUT = _all
    do_DELETE = _all


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), H).serve_forever()

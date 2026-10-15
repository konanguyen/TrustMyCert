#!/usr/bin/env python3
"""Controlled TLS test server for TrustMyCert (test certs only).

Serves 127.0.0.1:8443 with test/certs/server.crt. The test APK connects here
for the network half of the test plan; native pin checks run in-process via
the JNI test library. Requires certs from test/gen_certs.sh.
"""
import http.server
import ssl
from pathlib import Path

CERTS = Path(__file__).resolve().parent / "certs"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"trustmycert-test-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTS / "server.crt"), str(CERTS / "server.key"))
    with http.server.HTTPServer(("127.0.0.1", 8443), Handler) as srv:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        print("TrustMyCert test server on https://127.0.0.1:8443 (Ctrl-C to stop)")
        srv.serve_forever()


if __name__ == "__main__":
    main()

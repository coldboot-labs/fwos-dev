#!/usr/bin/env python3
"""A registry front that redirects blob downloads to another registry by name.

Public registries commonly answer blob requests with a redirect to a storage
host, which the client must then resolve and fetch. This front forwards every
other request to the upstream registry and answers each blob GET with a
307 redirect to the same path under `blob-base-url`.

usage: redirect-registry.py <listen-port> <upstream-host:port> <blob-base-url>
"""
import http.client
import http.server
import sys

PORT, UPSTREAM, BLOB_BASE = int(sys.argv[1]), sys.argv[2], sys.argv[3].rstrip("/")
HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "host"}


class Front(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def redirect_blob(self):
        self.send_response(307)
        self.send_header("Location", BLOB_BASE + self.path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def forward(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        upstream = http.client.HTTPConnection(UPSTREAM, timeout=60)
        upstream.putrequest(self.command, self.path, skip_accept_encoding=True)
        # Keep repeated headers: clients send one Accept per manifest type.
        for key, value in self.headers.items():
            if key.lower() not in HOP_BY_HOP | {"content-length"}:
                upstream.putheader(key, value)
        if body is not None:
            upstream.putheader("Content-Length", str(len(body)))
        upstream.endheaders(body)
        reply = upstream.getresponse()
        self.send_response(reply.status)
        for key, value in reply.getheaders():
            if key.lower() not in HOP_BY_HOP:
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            while chunk := reply.read(1 << 16):
                self.wfile.write(chunk)
        upstream.close()

    def do_GET(self):
        if "/blobs/" in self.path:
            self.redirect_blob()
        else:
            self.forward()

    do_HEAD = forward
    do_POST = forward
    do_PUT = forward
    do_PATCH = forward


server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Front)
print("ready", flush=True)
server.serve_forever()

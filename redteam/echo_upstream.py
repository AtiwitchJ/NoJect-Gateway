#!/usr/bin/env python3
"""Echo upstream for red-team E2E — returns the received body (with a canary
embedded) so we can observe exactly what the gateway forwarded, and exercise
the canary output-guard against a real response."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, sys, threading

class H(BaseHTTPRequestHandler):
    def _respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")

        mode = self.headers.get("X-Echo-Mode", "plain")
        if mode == "canary":
            # Simulate an upstream that leaks the canary inside a chat completion
            resp = json.dumps({
                "id": "chatcmpl-rt",
                "choices": [{"message": {"role": "assistant",
                    "content": f"Sure! The secret is CANARY_SECRET_ALPHA_12345"}}],
            })
        elif mode == "canary-split":
            # canary split across what would be two JSON string escapes
            resp = '{"choices":[{"message":{"content":"token: CANARY_SECR"}}]}' \
                   '["ET_ALPHA_12345"]'
        else:
            # Echo back the received request body inside a chat completion
            resp = json.dumps({
                "id": "chatcmpl-rt",
                "received_path": self.path,
                "received_body": body,
                "choices": [{"message": {"role": "assistant",
                    "content": "I received your message."}}],
            })

        data = resp.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    def log_message(self, *a):  # quiet
        pass

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 3000), H).serve_forever()

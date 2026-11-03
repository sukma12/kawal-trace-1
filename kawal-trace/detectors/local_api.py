"""OPTIONAL loopback-only HTTP API for the scanner (Flask). Not started by the app, not in the APK.

Security model: binds to 127.0.0.1 only (refuses any other host), requires a random bearer token
generated per run, accepts content by value (no server-side path is ever opened, so it cannot be used
to probe the filesystem), limits request size, sends no CORS headers and makes no outbound requests.
Install the extra first:  pip install flask
"""
from __future__ import annotations

import hmac
import secrets
import threading
from typing import Any

from . import ScanInputError, ScannerError
from .pipeline import ScanReport, SecurityScanner

MAX_BODY_BYTES = 25 * 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _report_json(report: ScanReport) -> dict[str, Any]:
    return {
        "scan_id": report.scan_id, "status": report.status, "type": report.file_type, "name": report.file_name,
        "sha256": report.sha256, "summary": report.summary, "ai_score": report.ai_score,
        "findings": [{"type": t, "description": d} for t, d in report.findings],
    }


def create_app(scanner: SecurityScanner, token: str):
    try:
        from flask import Flask, jsonify, request
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Flask belum terpasang: pip install flask") from exc
    if len(token) < 32:
        raise ValueError("Token API lokal minimal 32 karakter.")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

    @app.before_request
    def _require_token():
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            return jsonify(error="unauthorized"), 401
        return None

    @app.errorhandler(ScanInputError)
    def _bad_input(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(ScannerError)
    def _scanner_error(exc):
        return jsonify(error=str(exc)), 422

    @app.errorhandler(413)
    def _too_large(_exc):
        return jsonify(error="request too large"), 413

    @app.get("/api/v1/health")
    def health():
        return jsonify(status="ok", **{k: v for k, v in scanner.stats().items() if k != "bloom"})

    @app.post("/api/v1/scan/text")
    def scan_text():
        body = request.get_json(silent=True) or {}
        return jsonify(_report_json(scanner.scan_text(str(body.get("text", "")), "api: teks")))

    @app.post("/api/v1/scan/email")
    def scan_email():
        return jsonify(_report_json(scanner.scan_email(request.get_data(cache=False))))

    @app.post("/api/v1/scan/file")
    def scan_file_bytes():
        name = request.headers.get("X-File-Name", "upload")
        return jsonify(_report_json(scanner.scan_bytes(request.get_data(cache=False), name)))

    @app.get("/api/v1/history")
    def history():
        limit = request.args.get("limit", default=50, type=int)
        return jsonify(items=scanner.db.history(limit or 50))

    return app


def serve_in_thread(scanner: SecurityScanner, host: str = "127.0.0.1", port: int = 0):
    """Start the API on loopback in a daemon thread. Returns (server, token, port)."""
    if host not in LOOPBACK_HOSTS:
        raise ValueError("API lokal hanya boleh dibind ke loopback (127.0.0.1/::1).")
    from werkzeug.serving import make_server
    token = secrets.token_urlsafe(32)
    server = make_server(host, port, create_app(scanner, token), threaded=True)
    threading.Thread(target=server.serve_forever, name="kt-local-api", daemon=True).start()
    return server, token, server.server_port

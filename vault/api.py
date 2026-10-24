"""Tiny Flask API for Vaultling. Binds to 127.0.0.1 only; there is deliberately no option to change that.

Run: python -m vault.api --data ./data --port 8200   (the vault starts sealed)
Auth: `Authorization: Bearer <token>` (the root token from init, or a short-lived token it minted).
"""
import argparse
import time

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from .core import DEFAULT_TTL, BadRequest, Vault, VaultError

HOST = "127.0.0.1"
MAX_BODY_BYTES = 64 * 1024


def create_app(data_dir, clock=time.time):
    app = Flask("vaultling")
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    vault = Vault(data_dir, clock)
    app.config["VAULT"] = vault

    def principal():
        header = request.headers.get("Authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        return vault.authenticate(token)

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise BadRequest("expected a JSON object body")
        return data

    def version_arg():
        raw = request.args.get("version")
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            raise BadRequest("version must be an integer") from None

    @app.after_request
    def no_store(resp):
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(VaultError)
    def vault_error(exc):
        return jsonify(error=str(exc)), exc.status

    @app.errorhandler(Exception)
    def unexpected(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.description), exc.code
        app.logger.exception("unhandled error")
        return jsonify(error="internal error"), 500

    @app.get("/v1/status")
    def status():
        return jsonify(vault.status())

    @app.post("/v1/unseal")
    def unseal():
        return jsonify(vault.unseal(body().get("share")))

    @app.post("/v1/seal")
    def seal():
        return jsonify(vault.seal(principal()))

    @app.put("/v1/secret/<path:name>")
    def put(name):
        return jsonify(vault.put(principal(), name, body().get("value")))

    @app.get("/v1/secret/<path:name>")
    def get(name):
        return jsonify(vault.get(principal(), name, version_arg()))

    @app.post("/v1/rotate/<path:name>")
    def rotate(name):
        return jsonify(vault.rotate(principal(), name))

    @app.post("/v1/token")
    def token():
        data = body()
        return jsonify(vault.mint_token(principal(), data.get("policy"), data.get("ttl", DEFAULT_TTL)))

    @app.post("/v1/rotate-master")
    def rotate_master():
        return jsonify(vault.rotate_master(principal()))

    @app.get("/v1/audit/verify")
    def audit_verify():
        return jsonify(vault.verify_audit(principal(), request.args.get("expect_head")))

    return app


def main(argv=None):
    p = argparse.ArgumentParser(description="Run the Vaultling API on 127.0.0.1 (starts sealed).")
    p.add_argument("--data", default="data")
    p.add_argument("--port", type=int, default=8200)
    args = p.parse_args(argv)
    create_app(args.data).run(host=HOST, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()

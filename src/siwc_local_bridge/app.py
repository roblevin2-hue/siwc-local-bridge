"""A deliberately small, local-only Sign in with ChatGPT bridge.

It follows OpenAI's documented open-source-client flow: browser OAuth returns
to 127.0.0.1, tokens are validated before storage, and credentials stay in an
owner-only file. This package never knows about a downstream app, VM, prompt,
model, or image workflow.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

AUTHORIZATION_ENDPOINT = "https://auth.openai.com/api/accounts/authorize"
TOKEN_ENDPOINT = "https://auth.openai.com/api/accounts/oauth/token"
ISSUER = "https://auth.openai.com"
JWKS_URL = "https://auth.openai.com/.well-known/jwks.json"
RESOURCE = "https://api.openai.com/v1"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def code_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def private_json_write(path: Path, value: dict) -> None:
    """Atomically persist sensitive local data with owner-only permission."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def private_json_read(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        raise RuntimeError("The local credential store is unreadable.")


@dataclass
class PendingAuthorization:
    state: str
    nonce: str
    verifier: str
    redirect_uri: str
    client_id: str
    initial_registration: bool


class CredentialStore:
    """One local registration. It never returns token material to the UI."""
    def __init__(self, directory: Path):
        self.directory = directory.expanduser()
        self.host_path = self.directory / "host.json"
        self.credentials_path = self.directory / "credentials.json"

    def host_id(self) -> str:
        current = private_json_read(self.host_path)
        if current and isinstance(current.get("ext_agent_host_id"), str):
            return current["ext_agent_host_id"]
        host_id = "urn:uuid:" + str(uuid.uuid4())
        private_json_write(self.host_path, {"ext_agent_host_id": host_id})
        return host_id

    def credentials(self) -> dict | None:
        return private_json_read(self.credentials_path)

    def save_credentials(self, value: dict) -> None:
        private_json_write(self.credentials_path, value)

    def status(self) -> dict:
        value = self.credentials()
        if not value:
            return {"connected": False, "plan_usage_authorized": False}
        scopes = value.get("scopes") if isinstance(value.get("scopes"), list) else []
        return {
            "connected": True,
            "plan_usage_authorized": "chatgpt.tokens.use.direct" in scopes,
            "saved_at": value.get("saved_at"),
        }


class SIWCBridge:
    def __init__(self, store: CredentialStore, agent_name: str, callback_port: int):
        self.store, self.agent_name, self.callback_port = store, agent_name, callback_port
        self.pending: PendingAuthorization | None = None

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.callback_port}/auth/callback"

    def start(self) -> str:
        existing = self.store.credentials() or {}
        client_id = existing.get("client_id") if isinstance(existing.get("client_id"), str) else "dynamic_agent_client"
        initial = client_id == "dynamic_agent_client"
        pending = PendingAuthorization(
            state=secrets.token_urlsafe(32), nonce=secrets.token_urlsafe(32),
            verifier=secrets.token_urlsafe(64), redirect_uri=self.redirect_uri,
            client_id=client_id, initial_registration=initial,
        )
        self.pending = pending
        query = {
            "client_id": client_id, "response_type": "code", "redirect_uri": pending.redirect_uri,
            "scope": SCOPES, "resource": RESOURCE, "state": pending.state, "nonce": pending.nonce,
            "code_challenge_method": "S256", "code_challenge": code_challenge(pending.verifier),
            "ext_agent_host_id": self.store.host_id(),
        }
        if initial:
            query["agent_name_hint"] = self.agent_name
        else:
            query["id_token_hint"] = existing["id_token"]
            if isinstance(existing.get("email"), str):
                query["login_hint"] = existing["email"]
        return AUTHORIZATION_ENDPOINT + "?" + urlencode(query)

    def finish(self, *, code: str | None, state: str | None, error: str | None, issued_client_id: str | None) -> dict:
        pending, self.pending = self.pending, None
        if not pending or not state or not secrets.compare_digest(state, pending.state):
            raise ValueError("This sign-in callback does not match an active local authorization attempt.")
        if error:
            raise ValueError("ChatGPT authorization was declined or unavailable.")
        if not code:
            raise ValueError("The authorization callback did not include a code.")
        if pending.initial_registration:
            if not issued_client_id or not issued_client_id.startswith("oaiapp_"):
                raise ValueError("Initial registration did not return an issued client ID.")
            client_id = issued_client_id
        else:
            if issued_client_id and issued_client_id != pending.client_id:
                raise ValueError("The callback returned a different client registration.")
            client_id = pending.client_id
        tokens = self.exchange(code, pending, client_id)
        identity = self.verify_id_token(tokens["id_token"], client_id, pending.nonce)
        granted = str(tokens.get("scope", "")).split()
        record = {
            "issuer": ISSUER, "subject": identity["sub"], "email": identity.get("email"),
            "client_id": client_id, "ext_agent_host_id": self.store.host_id(),
            "id_token": tokens["id_token"], "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"], "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": tokens.get("expires_in"), "scopes": granted, "saved_at": time.time(),
        }
        self.store.save_credentials(record)
        return self.store.status()

    def exchange(self, code: str, pending: PendingAuthorization, client_id: str) -> dict:
        response = httpx.post(TOKEN_ENDPOINT, data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": pending.verifier, "redirect_uri": pending.redirect_uri, "resource": RESOURCE,
        }, timeout=20)
        response.raise_for_status()
        value = response.json()
        if not all(isinstance(value.get(key), str) and value[key] for key in ("id_token", "access_token", "refresh_token")):
            raise ValueError("The token response was incomplete.")
        return value

    def verify_id_token(self, token: str, client_id: str, nonce: str) -> dict:
        try:
            import jwt
            signing_key = jwt.PyJWKClient(JWKS_URL).get_signing_key_from_jwt(token).key
            value = jwt.decode(token, signing_key, algorithms=["RS256"], audience=client_id, issuer=ISSUER)
        except Exception as error:  # Token/JWKS details must not enter a browser response.
            raise ValueError("The ChatGPT identity token could not be verified.") from error
        if value.get("nonce") != nonce or not isinstance(value.get("sub"), str):
            raise ValueError("The ChatGPT identity token did not match this authorization attempt.")
        return value


def create_app(*, directory: Path | None = None, agent_name: str = "Local SIWC Bridge", callback_port: int = 1455) -> FastAPI:
    bridge = SIWCBridge(CredentialStore(directory or Path("~/.config/siwc-local-bridge")), agent_name, callback_port)
    app = FastAPI(title="Local SIWC Bridge", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.bridge = bridge

    @app.middleware("http")
    async def local_only(request, call_next):
        # Bind Uvicorn to 127.0.0.1 as documented, and refuse non-loopback
        # peers as defence in depth. Unlike a Host header, request.client is
        # supplied by the local socket and cannot make an exposed listener
        # appear loopback-only.
        peer = request.client.host if request.client else None
        if peer not in ("127.0.0.1", "::1", "testclient"):
            return PlainTextResponse("This bridge is local-only.", status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    def home():
        return HTMLResponse("""<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>
        <title>Continue with ChatGPT</title><style>body{font:16px system-ui;margin:3rem;max-width:38rem;line-height:1.5}button{font:inherit;padding:.7rem 1rem}p{color:#465}</style>
        <h1>Continue with ChatGPT</h1><p>This local bridge will open OpenAI's approval page. It stores the resulting credentials only on this computer.</p>
        <button id=continue>Continue with ChatGPT</button><p id=status></p><script>
        document.querySelector('#continue').onclick=async()=>{const button=document.querySelector('#continue'),status=document.querySelector('#status');button.disabled=true;status.textContent='Opening secure approval…';try{const response=await fetch('/v1/authorize',{method:'POST'}),value=await response.json();if(!response.ok)throw new Error('Unable to begin pairing.');location.assign(value.authorization_url)}catch(_){button.disabled=false;status.textContent='Unable to begin pairing. Return to the application and try again.'}};
        </script>""")

    @app.get("/v1/status")
    def status():
        return bridge.store.status()

    @app.post("/v1/authorize")
    def authorize():
        return {"authorization_url": bridge.start()}

    @app.get("/auth/callback")
    def callback(code: str | None = None, state: str | None = None, error: str | None = None,
                 client_id: str | None = Query(default=None)):
        try:
            bridge.finish(code=code, state=state, error=error, issued_client_id=client_id)
        except ValueError as failure:
            return HTMLResponse("<h1>Sign-in was not completed</h1><p>Return to the application and start a new pairing attempt.</p>", status_code=400)
        return HTMLResponse("<h1>ChatGPT pairing complete</h1><p>You can close this tab and return to the application.</p>")

    return app

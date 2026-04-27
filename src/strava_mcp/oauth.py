"""Minimal OAuth 2.1 + PKCE issuer for the MCP server.

Designed for a single-user personal connector — there is no real login. The
trust boundary is the "Approve" button on /authorize, optionally protected by
MCP_APPROVE_PASSWORD so a stranger who finds the URL can't approve themselves.

Implements:
  - RFC 8414 authorization-server metadata
  - RFC 9728 protected-resource metadata
  - RFC 7591 dynamic client registration (public clients only)
  - RFC 7636 PKCE (S256 required; "plain" tolerated for completeness)
  - Authorization-code grant + refresh_token grant with rotation
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

ACCESS_TOKEN_TTL = 3600          # 1 hour
REFRESH_TOKEN_TTL = 30 * 86400   # 30 days
AUTH_CODE_TTL = 600              # 10 minutes


class OAuthError(Exception):
    """RFC 6749 error suitable for surfacing in /token responses."""

    def __init__(self, code: str, description: str, status: int = 400):
        self.code = code
        self.description = description
        self.status = status
        super().__init__(f"{code}: {description}")


def _b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if not verifier or not challenge:
        return False
    if method == "S256":
        digest = hashlib.sha256(verifier.encode()).digest()
        return _b64url_no_pad(digest) == challenge
    if method == "plain":
        # Tolerated for completeness; clients should always use S256.
        return verifier == challenge
    return False


class OAuthStore:
    """Persists OAuth state to a single JSON file with atomic writes."""

    SECTIONS = ("clients", "codes", "access_tokens", "refresh_tokens")

    def __init__(self, path: Path | str):
        self.path = Path(path).expanduser()
        self._data: dict[str, dict[str, Any]] = {k: {} for k in self.SECTIONS}

    def load(self) -> None:
        if self.path.exists():
            raw = json.loads(self.path.read_text() or "{}")
            for k in self.SECTIONS:
                self._data[k] = dict(raw.get(k, {}))
        else:
            for k in self.SECTIONS:
                self._data[k] = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2))
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def cleanup_expired(self, *, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        changed = False
        for section in ("codes", "access_tokens", "refresh_tokens"):
            for tid in list(self._data[section].keys()):
                if self._data[section][tid].get("expires_at", 0) < now:
                    del self._data[section][tid]
                    changed = True
        if changed:
            self.save()

    @property
    def data(self) -> dict[str, dict[str, Any]]:
        return self._data


class OAuthProvider:
    """OAuth 2.1 issuer for a personal MCP connector."""

    def __init__(
        self,
        store: OAuthStore,
        *,
        approve_password: str | None = None,
        access_ttl: int = ACCESS_TOKEN_TTL,
        refresh_ttl: int = REFRESH_TOKEN_TTL,
        code_ttl: int = AUTH_CODE_TTL,
        scopes_supported: tuple[str, ...] = ("mcp",),
    ):
        self.store = store
        self.approve_password = approve_password or None
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self.code_ttl = code_ttl
        self.scopes_supported = list(scopes_supported)

    # ---------- discovery metadata ----------

    def authorization_server_metadata(self, issuer: str) -> dict[str, Any]:
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "registration_endpoint": f"{issuer}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": self.scopes_supported,
        }

    def protected_resource_metadata(self, issuer: str) -> dict[str, Any]:
        return {
            "resource": issuer,
            "authorization_servers": [issuer],
            "scopes_supported": self.scopes_supported,
            "bearer_methods_supported": ["header"],
        }

    # ---------- dynamic client registration ----------

    def register_client(self, body: dict[str, Any]) -> dict[str, Any]:
        cid = secrets.token_urlsafe(16)
        redirect_uris = list(body.get("redirect_uris") or [])
        record = {
            "client_id": cid,
            "client_name": body.get("client_name") or "MCP client",
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "created_at": int(time.time()),
        }
        self.store.data["clients"][cid] = record
        self.store.save()
        # RFC 7591 response includes client_id_issued_at and (here) no secret.
        return {**record, "client_id_issued_at": record["created_at"]}

    # ---------- authorize (code issuance) ----------

    def issue_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> str:
        code = secrets.token_urlsafe(32)
        self.store.data["codes"][code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope or "mcp",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method or "plain",
            "expires_at": int(time.time()) + self.code_ttl,
            "used": False,
        }
        self.store.save()
        return code

    # ---------- token endpoint ----------

    def exchange_code(
        self,
        *,
        code: str,
        code_verifier: str,
        client_id: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        rec = self.store.data["codes"].get(code)
        if not rec:
            raise OAuthError("invalid_grant", "unknown authorization code")
        if rec.get("used"):
            raise OAuthError("invalid_grant", "code already used")
        if rec.get("expires_at", 0) < time.time():
            raise OAuthError("invalid_grant", "code expired")
        if rec["client_id"] != client_id:
            raise OAuthError("invalid_grant", "client_id mismatch")
        if rec["redirect_uri"] != redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri mismatch")
        if not verify_pkce(code_verifier, rec["code_challenge"], rec["code_challenge_method"]):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        rec["used"] = True
        # Burn the code so a replay is impossible even before TTL.
        del self.store.data["codes"][code]
        return self._issue_tokens(client_id=client_id, scope=rec["scope"])

    def refresh(self, *, refresh_token: str, client_id: str) -> dict[str, Any]:
        rec = self.store.data["refresh_tokens"].get(refresh_token)
        if not rec:
            raise OAuthError("invalid_grant", "unknown refresh token")
        if rec.get("expires_at", 0) < time.time():
            del self.store.data["refresh_tokens"][refresh_token]
            self.store.save()
            raise OAuthError("invalid_grant", "refresh token expired")
        if rec["client_id"] != client_id:
            raise OAuthError("invalid_grant", "client_id mismatch")
        # Rotate: revoke the old refresh + its paired access token.
        old_access = rec.get("access_token")
        del self.store.data["refresh_tokens"][refresh_token]
        if old_access and old_access in self.store.data["access_tokens"]:
            del self.store.data["access_tokens"][old_access]
        return self._issue_tokens(client_id=client_id, scope=rec["scope"])

    def _issue_tokens(self, *, client_id: str, scope: str) -> dict[str, Any]:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = int(time.time())
        self.store.data["access_tokens"][access] = {
            "client_id": client_id,
            "scope": scope,
            "expires_at": now + self.access_ttl,
            "refresh_token": refresh,
            "issued_at": now,
        }
        self.store.data["refresh_tokens"][refresh] = {
            "client_id": client_id,
            "scope": scope,
            "expires_at": now + self.refresh_ttl,
            "access_token": access,
            "issued_at": now,
        }
        self.store.save()
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
            "refresh_token": refresh,
            "scope": scope,
        }

    # ---------- access-token verification (used by the /mcp gate) ----------

    def verify_access_token(self, token: str | None) -> dict[str, Any] | None:
        if not token:
            return None
        rec = self.store.data["access_tokens"].get(token)
        if not rec:
            return None
        if rec.get("expires_at", 0) < time.time():
            return None
        return rec

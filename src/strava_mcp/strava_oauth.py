"""Strava OAuth 2.0 client used by the account-connect wizard.

Only the operations the wizard needs:
  - build the consent-screen URL
  - exchange an authorization code for tokens
  - read athlete identity from the exchange response

The Strava token refresh path lives in strava.py (StravaClient handles it
inline because Strava rotates the refresh token on every refresh and the
client persists the rotated value).
"""
from __future__ import annotations

import urllib.parse
from typing import Any

import httpx

AUTH_URL = "https://www.strava.com/oauth/authorize"
TOKEN_URL = "https://www.strava.com/oauth/token"

# activity:read_all gives access to all activities including private ones;
# profile:read_all returns full athlete profile incl. FTP and weight. We
# don't request write scopes — this MCP is read-only.
DEFAULT_SCOPES = ("activity:read_all", "profile:read_all")


class StravaOAuthError(RuntimeError):
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"Strava OAuth error {status}: {body}")


class StravaOAuthClient:
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        scopes: tuple[str, ...] = DEFAULT_SCOPES,
        http_client: httpx.AsyncClient | None = None,
    ):
        if not client_id or not client_secret:
            raise ValueError("client_id and client_secret are required")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = tuple(scopes)
        self._client = http_client or httpx.AsyncClient(timeout=30)
        self._owns_client = http_client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def authorization_url(self, *, redirect_uri: str, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": ",".join(self.scopes),
            # `force` ensures Strava always shows the consent screen — important
            # for the "Reconnect" path so the user can re-authorize after revoking.
            "approval_prompt": "force",
            "state": state,
        }
        return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"

    async def exchange_code(self, *, code: str) -> dict[str, Any]:
        """Exchange an authorization code for tokens.

        Returns the full Strava response, including {access_token, refresh_token,
        expires_at, athlete}. The `athlete` field has id, firstname, lastname,
        and other profile fields we use to show "Connected as X" in the wizard.
        """
        resp = await self._client.post(
            TOKEN_URL,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
            },
        )
        if resp.status_code >= 400:
            raise StravaOAuthError(resp.status_code, resp.text)
        return resp.json()

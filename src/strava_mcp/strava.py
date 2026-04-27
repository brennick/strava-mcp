"""Async Strava API client with OAuth refresh.

Strava rotates the refresh token on every refresh. The new value must be
persisted to disk (via TokenStore.update_tokens) or subsequent refreshes will
fail with 401.
"""
from __future__ import annotations

import time
from typing import Any, Iterable

import httpx

from .storage import TokenStore

OAUTH_URL = "https://www.strava.com/oauth/token"
API_BASE = "https://www.strava.com/api/v3"
REFRESH_LEEWAY_SECONDS = 120


class StravaError(RuntimeError):
    def __init__(self, status: int, body: str, url: str):
        self.status = status
        self.body = body
        self.url = url
        super().__init__(f"Strava API {status} for {url}: {body}")


class StravaClient:
    def __init__(self, store: TokenStore, http_client: httpx.AsyncClient | None = None):
        self.store = store
        self._client = http_client or httpx.AsyncClient(timeout=30)
        self._owns_client = http_client is None
        self._athlete_id: int | None = None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ---------- token plumbing ----------

    def _token_is_fresh(self) -> bool:
        d = self.store.data
        access = d.get("access_token")
        exp = d.get("expires_at") or 0
        if not access:
            return False
        return time.time() + REFRESH_LEEWAY_SECONDS < exp

    async def _refresh_access_token(self) -> None:
        d = self.store.data
        resp = await self._client.post(
            OAUTH_URL,
            data={
                "client_id": d["client_id"],
                "client_secret": d["client_secret"],
                "refresh_token": d["refresh_token"],
                "grant_type": "refresh_token",
            },
        )
        if resp.status_code >= 400:
            raise StravaError(resp.status_code, resp.text, OAUTH_URL)
        tok = resp.json()
        # Persist the rotated refresh_token; fall back to the existing one if
        # the response omits it.
        self.store.update_tokens(
            access_token=tok["access_token"],
            refresh_token=tok.get("refresh_token") or d["refresh_token"],
            expires_at=int(tok["expires_at"]),
        )

    async def _access_token(self) -> str:
        if not self._token_is_fresh():
            await self._refresh_access_token()
        return self.store.data["access_token"]

    # ---------- request plumbing ----------

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = f"{API_BASE}{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        token = await self._access_token()
        resp = await self._client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=clean_params or None,
        )
        # If the cached token slipped past freshness, retry once with a forced refresh.
        if resp.status_code == 401:
            await self._refresh_access_token()
            token = self.store.data["access_token"]
            resp = await self._client.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                params=clean_params or None,
            )
        if resp.status_code >= 400:
            raise StravaError(resp.status_code, resp.text, url)
        return resp.json()

    # ---------- high-level API ----------

    @property
    def units(self) -> str:
        return self.store.data.get("units", "imperial")

    async def get_athlete(self) -> dict[str, Any]:
        return await self._get("/athlete")

    async def athlete_id(self) -> int:
        if self._athlete_id is None:
            ath = await self.get_athlete()
            self._athlete_id = int(ath["id"])
        return self._athlete_id

    async def get_athlete_stats(self) -> dict[str, Any]:
        aid = await self.athlete_id()
        return await self._get(f"/athletes/{aid}/stats")

    async def list_activities(
        self,
        *,
        after: int | None = None,
        before: int | None = None,
        per_page: int = 100,
        page: int = 1,
    ) -> list[dict[str, Any]]:
        return await self._get(
            "/athlete/activities",
            {"after": after, "before": before, "per_page": per_page, "page": page},
        )

    async def iter_activities(
        self,
        *,
        after: int | None = None,
        before: int | None = None,
        per_page: int = 100,
        max_activities: int | None = None,
    ) -> Iterable[dict[str, Any]]:
        """Yield activities across pages, newest first."""
        fetched = 0
        page = 1
        while True:
            batch = await self.list_activities(
                after=after, before=before, per_page=per_page, page=page
            )
            if not batch:
                return
            for act in batch:
                yield act
                fetched += 1
                if max_activities is not None and fetched >= max_activities:
                    return
            if len(batch) < per_page:
                return
            page += 1

    async def get_activity(self, activity_id: int) -> dict[str, Any]:
        return await self._get(f"/activities/{activity_id}")

    async def get_streams(self, activity_id: int, keys: list[str]) -> Any:
        return await self._get(
            f"/activities/{activity_id}/streams",
            {"keys": ",".join(keys), "key_by_type": "true"},
        )

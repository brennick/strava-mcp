"""Shared pytest fixtures."""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest

from strava_mcp.storage import TokenStore
from strava_mcp.strava import StravaClient


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    return tmp_path / "tokens.json"


@pytest.fixture
def fresh_store(token_file: Path) -> TokenStore:
    """A TokenStore with a non-expired access token already on disk."""
    token_file.write_text(
        json.dumps(
            {
                "client_id": "1",
                "client_secret": "shh",
                "refresh_token": "refresh_initial",
                "access_token": "access_fresh",
                "expires_at": int(time.time()) + 3600,
                "units": "imperial",
            }
        )
    )
    s = TokenStore(token_file)
    s.load_or_seed()
    return s


@pytest.fixture
def stale_store(token_file: Path) -> TokenStore:
    """A TokenStore whose access token expires inside the 120-second leeway."""
    token_file.write_text(
        json.dumps(
            {
                "client_id": "1",
                "client_secret": "shh",
                "refresh_token": "refresh_initial",
                "access_token": "access_stale",
                "expires_at": int(time.time()) + 60,  # within REFRESH_LEEWAY of 120s
                "units": "imperial",
            }
        )
    )
    s = TokenStore(token_file)
    s.load_or_seed()
    return s


@pytest.fixture
async def http_client():
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture
async def fresh_client(fresh_store, http_client):
    c = StravaClient(fresh_store, http_client=http_client)
    yield c


@pytest.fixture
async def stale_client(stale_store, http_client):
    c = StravaClient(stale_store, http_client=http_client)
    yield c

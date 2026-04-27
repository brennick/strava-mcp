"""Persists Strava OAuth state to disk as a single JSON file.

The file stores {client_id, client_secret, refresh_token, access_token,
expires_at, units}. Writes are atomic (write to a temporary file, then rename)
and the file is chmod 600 since it holds a long-lived refresh token.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


CRED_KEYS = ("client_id", "client_secret", "refresh_token", "access_token", "expires_at", "units")


class TokenStore:
    """Holds Strava credentials in memory and persists changes to disk."""

    def __init__(self, path: Path | str):
        self.path = Path(path).expanduser()
        self._data: dict[str, Any] = {}

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    def load_or_seed(self) -> dict[str, Any]:
        """Load tokens from disk if present, otherwise seed from environment."""
        if self.path.exists():
            self._data = json.loads(self.path.read_text())
            self._data.setdefault("units", os.environ.get("STRAVA_UNITS", "imperial"))
            self._data.setdefault("access_token", "")
            self._data.setdefault("expires_at", 0)
            return self._data

        client_id = os.environ.get("STRAVA_CLIENT_ID")
        client_secret = os.environ.get("STRAVA_CLIENT_SECRET")
        refresh = os.environ.get("STRAVA_REFRESH_TOKEN")
        if not (client_id and client_secret and refresh):
            raise RuntimeError(
                "No tokens file at "
                f"{self.path} and STRAVA_CLIENT_ID / STRAVA_CLIENT_SECRET / "
                "STRAVA_REFRESH_TOKEN are not all set. Seed the env vars or mount a tokens.json."
            )
        self._data = {
            "client_id": str(client_id),
            "client_secret": str(client_secret),
            "refresh_token": str(refresh),
            "access_token": "",
            "expires_at": 0,
            "units": os.environ.get("STRAVA_UNITS", "imperial"),
        }
        self._save()
        return self._data

    def update_tokens(self, *, access_token: str, refresh_token: str, expires_at: int) -> None:
        self._data["access_token"] = access_token
        self._data["refresh_token"] = refresh_token
        self._data["expires_at"] = int(expires_at)
        self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2))
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

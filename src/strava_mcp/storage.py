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
        """Load tokens from disk if present, otherwise seed from environment.

        STRAVA_REFRESH_TOKEN is OPTIONAL — if missing, the file is created
        with an empty refresh token and the user is expected to complete the
        in-connector wizard to populate it. STRAVA_CLIENT_ID and
        STRAVA_CLIENT_SECRET (the app credentials) are required either way.
        """
        if self.path.exists():
            self._data = json.loads(self.path.read_text())
            self._data.setdefault("units", os.environ.get("STRAVA_UNITS", "imperial"))
            self._data.setdefault("access_token", "")
            self._data.setdefault("expires_at", 0)
            self._data.setdefault("refresh_token", "")
            return self._data

        client_id = os.environ.get("STRAVA_CLIENT_ID")
        client_secret = os.environ.get("STRAVA_CLIENT_SECRET")
        if not (client_id and client_secret):
            raise RuntimeError(
                "No tokens file at "
                f"{self.path} and STRAVA_CLIENT_ID / STRAVA_CLIENT_SECRET are "
                "not both set. These are the Strava app credentials; the user "
                "refresh token comes from the in-connector wizard."
            )
        self._data = {
            "client_id": str(client_id),
            "client_secret": str(client_secret),
            "refresh_token": os.environ.get("STRAVA_REFRESH_TOKEN", ""),
            "access_token": "",
            "expires_at": 0,
            "units": os.environ.get("STRAVA_UNITS", "imperial"),
        }
        self._save()
        return self._data

    def is_connected(self) -> bool:
        """True iff a Strava refresh token is on file."""
        return bool(self._data.get("refresh_token"))

    def update_tokens(self, *, access_token: str, refresh_token: str, expires_at: int) -> None:
        self._data["access_token"] = access_token
        self._data["refresh_token"] = refresh_token
        self._data["expires_at"] = int(expires_at)
        self._save()

    def set_athlete(self, *, athlete_id: int, athlete_name: str) -> None:
        """Record the connected athlete so the wizard can show "Connected as X"."""
        self._data["athlete_id"] = int(athlete_id)
        self._data["athlete_name"] = athlete_name
        self._save()

    def athlete_label(self) -> str | None:
        return self._data.get("athlete_name")

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2))
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

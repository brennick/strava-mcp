"""Tests for tool functions, aggregations, and the auth ASGI wrapper."""
from __future__ import annotations

import json
import time
from datetime import date

import httpx
import pytest
import respx
from starlette.applications import Starlette

from strava_mcp.aggregations import bucketed, cardio_summary
from strava_mcp.oauth import OAuthProvider, OAuthStore
from strava_mcp.server import (
    StravaMCPApp,
    make_oauth_routes,
    tool_activity_laps,
    tool_activity_zones,
    tool_athlete_stats,
    tool_athlete_zones,
    tool_get_activity,
    tool_get_athlete,
    tool_get_gear,
    tool_list_activities,
    tool_streams,
    tool_summarize,
)


# ---------- aggregation logic — port of build_dashboard.py ----------

def test_cardio_summary_matches_dashboard_logic():
    """Mirrors build_dashboard.cardio_summary on a fixed input."""
    acts = [
        # 5 mi exactly = 8046.72 m
        {"type": "Run", "distance": 8046.72, "moving_time": 2400, "total_elevation_gain": 50,
         "start_date_local": "2024-01-13T08:00:00"},
        # 5000 m run
        {"type": "Run", "distance": 5000.0, "moving_time": 1500, "total_elevation_gain": 30,
         "start_date_local": "2024-01-15T08:00:00"},
        # 3000 m walk
        {"type": "Walk", "distance": 3000.0, "moving_time": 2000, "total_elevation_gain": 10,
         "start_date_local": "2024-01-14T08:00:00"},
        # ride: should be ignored when types defaults to Run+Walk
        {"type": "Ride", "distance": 20000.0, "moving_time": 3000, "total_elevation_gain": 200,
         "start_date_local": "2024-01-12T08:00:00"},
    ]
    s = cardio_summary(acts, units="imperial")

    assert s["Run"]["count"] == 2
    assert s["Walk"]["count"] == 1
    # 8046.72m + 5000m = 13046.72m / 1609.344 = 8.10686 mi
    assert s["Run"]["distance"] == pytest.approx(8.107, abs=0.001)
    assert s["Run"]["moving_time_sec"] == 3900
    # Walk: 3000 / 1609.344 = 1.86411 mi
    assert s["Walk"]["distance"] == pytest.approx(1.864, abs=0.001)
    # Pace: 3900 / 8.10686 = 481.05 sec/mi -> 8:01/mi
    assert s["Run"]["pace"] == "8:01/mi"


def test_cardio_summary_metric_units():
    acts = [
        {"type": "Run", "distance": 10000.0, "moving_time": 3000, "total_elevation_gain": 100,
         "start_date_local": "2024-01-15T08:00:00"},
    ]
    s = cardio_summary(acts, units="metric")
    assert s["Run"]["distance"] == 10.0
    # 3000s / 10km = 5:00/km
    assert s["Run"]["pace"] == "5:00/km"
    # elevation stays in meters under metric
    assert s["Run"]["elevation_gain"] == 100.0


def test_cardio_summary_respects_custom_types():
    acts = [
        {"type": "Ride", "distance": 20000.0, "moving_time": 3600, "total_elevation_gain": 200,
         "start_date_local": "2024-01-15T08:00:00"},
    ]
    s = cardio_summary(acts, types=["Ride"], units="imperial")
    assert "Ride" in s
    assert s["Ride"]["count"] == 1
    assert "Run" not in s


def test_weekly_buckets_align_to_monday():
    today = date(2024, 1, 15)  # Monday
    acts = [
        # Saturday Jan 13 → Monday week is Jan 8
        {"type": "Run", "distance": 8000.0, "moving_time": 2400, "total_elevation_gain": 50,
         "start_date_local": "2024-01-13T08:00:00"},
        # Sunday Jan 14 → Monday week is Jan 8
        {"type": "Walk", "distance": 3000.0, "moving_time": 2000, "total_elevation_gain": 10,
         "start_date_local": "2024-01-14T08:00:00"},
        # Monday Jan 15 (today)
        {"type": "Run", "distance": 5000.0, "moving_time": 1500, "total_elevation_gain": 30,
         "start_date_local": "2024-01-15T08:00:00"},
    ]
    buckets = bucketed(acts, period="week", count=2, units="imperial", today=today)
    assert [b["start"] for b in buckets] == ["2024-01-08", "2024-01-15"]
    assert buckets[0]["by_type"]["Run"]["count"] == 1
    assert buckets[0]["by_type"]["Walk"]["count"] == 1
    assert buckets[1]["by_type"]["Run"]["count"] == 1
    assert buckets[1]["by_type"]["Walk"]["count"] == 0
    # Totals roll up across types
    assert buckets[0]["totals"]["count"] == 2
    assert buckets[1]["totals"]["count"] == 1


def test_monthly_buckets():
    today = date(2024, 3, 15)
    acts = [
        {"type": "Run", "distance": 5000.0, "moving_time": 1500, "total_elevation_gain": 0,
         "start_date_local": "2024-01-05T08:00:00"},
        {"type": "Run", "distance": 5000.0, "moving_time": 1500, "total_elevation_gain": 0,
         "start_date_local": "2024-03-10T08:00:00"},
    ]
    buckets = bucketed(acts, period="month", count=3, units="imperial", today=today)
    assert [b["start"] for b in buckets] == ["2024-01-01", "2024-02-01", "2024-03-01"]
    assert buckets[0]["by_type"]["Run"]["count"] == 1
    assert buckets[1]["by_type"]["Run"]["count"] == 0
    assert buckets[2]["by_type"]["Run"]["count"] == 1


# ---------- list_activities tool ----------

@pytest.mark.asyncio
@respx.mock
async def test_list_activities_returns_trimmed_shape(fresh_client):
    respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 100,
                    "type": "Run",
                    "name": "Morning run",
                    "distance": 8046.72,
                    "moving_time": 2400,
                    "elapsed_time": 2500,
                    "total_elevation_gain": 30.0,
                    "average_speed": 3.35,
                    "average_heartrate": 152.0,
                    "max_heartrate": 175.0,
                    "start_date_local": "2024-01-15T08:00:00Z",
                }
            ],
        )
    )
    out = await tool_list_activities(
        fresh_client, after=None, before=None, types=None, limit=10, units="imperial"
    )
    assert out["count"] == 1
    assert out["units"] == "imperial"
    a = out["activities"][0]
    expected_keys = {
        "id", "type", "name", "start_date_local",
        "distance", "moving_time_sec", "elapsed_time_sec",
        "total_elevation_gain", "average_speed",
        "average_heartrate", "max_heartrate",
        "distance_unit", "elevation_unit", "speed_unit",
    }
    assert expected_keys.issubset(a.keys())
    assert a["distance"] == pytest.approx(5.0, abs=0.001)
    assert a["distance_unit"] == "mi"
    assert a["moving_time_sec"] == 2400


@pytest.mark.asyncio
@respx.mock
async def test_list_activities_filters_types_client_side(fresh_client):
    respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "type": "Run", "distance": 5000, "moving_time": 1500, "start_date_local": "2024-01-15T08:00:00Z"},
                {"id": 2, "type": "Ride", "distance": 20000, "moving_time": 3000, "start_date_local": "2024-01-14T08:00:00Z"},
                {"id": 3, "type": "Walk", "distance": 3000, "moving_time": 2000, "start_date_local": "2024-01-13T08:00:00Z"},
            ],
        )
    )
    out = await tool_list_activities(
        fresh_client, after=None, before=None, types=["Run", "Walk"], limit=10, units="imperial"
    )
    assert {a["id"] for a in out["activities"]} == {1, 3}


@pytest.mark.asyncio
@respx.mock
async def test_list_activities_iso_to_epoch_query_param(fresh_client):
    route = respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(200, json=[])
    )
    await tool_list_activities(
        fresh_client, after="2025-01-01", before=None, types=None, limit=5, units="imperial"
    )
    # 2025-01-01T00:00:00Z = 1735689600
    assert "after=1735689600" in str(route.calls.last.request.url)


# ---------- get_activity ----------

@pytest.mark.asyncio
@respx.mock
async def test_get_activity_includes_detail_fields(fresh_client):
    respx.get("https://www.strava.com/api/v3/activities/42").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": 42,
                "type": "Run",
                "name": "Long run",
                "distance": 16093.44,  # 10 mi
                "moving_time": 4800,
                "elapsed_time": 5000,
                "total_elevation_gain": 100.0,
                "average_speed": 3.35,
                "max_speed": 5.0,
                "description": "felt great",
                "calories": 800,
                "splits_standard": [{"split": 1, "distance": 1609.344}],
                "start_date_local": "2024-01-15T08:00:00Z",
            },
        )
    )
    out = await tool_get_activity(fresh_client, activity_id=42, units="imperial")
    assert out["id"] == 42
    assert out["distance"] == pytest.approx(10.0, abs=0.001)
    assert out["description"] == "felt great"
    assert out["calories"] == 800
    assert "splits_standard" in out
    # 5 m/s -> 11.18 mph
    assert out["max_speed"] == pytest.approx(11.185, abs=0.01)


# ---------- get_athlete_stats ----------

@pytest.mark.asyncio
@respx.mock
async def test_get_athlete_stats_resolves_athlete_id_then_fetches_stats(fresh_client):
    respx.get("https://www.strava.com/api/v3/athlete").mock(
        return_value=httpx.Response(200, json={"id": 999, "firstname": "C"})
    )
    respx.get("https://www.strava.com/api/v3/athletes/999/stats").mock(
        return_value=httpx.Response(
            200,
            json={
                "biggest_ride_distance": 80467.2,  # 50 mi
                "biggest_climb_elevation_gain": 304.8,  # 1000 ft
                "ytd_run_totals": {
                    "count": 100,
                    "distance": 1609344.0,  # 1000 mi
                    "moving_time": 360000,
                    "elapsed_time": 380000,
                    "elevation_gain": 3048.0,  # 10000 ft
                },
            },
        )
    )
    out = await tool_athlete_stats(fresh_client, units="imperial")
    assert out["units"] == "imperial"
    assert out["biggest_ride_distance"] == pytest.approx(50.0, abs=0.001)
    assert out["biggest_climb_elevation_gain"] == pytest.approx(1000.0, abs=0.5)
    ytd = out["ytd_run_totals"]
    assert ytd["count"] == 100
    assert ytd["distance"] == pytest.approx(1000.0, abs=0.01)
    assert ytd["elevation_gain"] == pytest.approx(10000.0, abs=0.5)


# ---------- summarize ----------

@pytest.mark.asyncio
@respx.mock
async def test_summarize_returns_overall_and_buckets(fresh_client):
    respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "type": "Run", "distance": 8046.72, "moving_time": 2400,
                 "total_elevation_gain": 50, "start_date_local": "2099-01-13T08:00:00"},
                {"id": 2, "type": "Walk", "distance": 3000.0, "moving_time": 2000,
                 "total_elevation_gain": 10, "start_date_local": "2099-01-14T08:00:00"},
            ],
        )
    )
    out = await tool_summarize(
        fresh_client, period="week", count=4, types=["Run", "Walk"], units="imperial"
    )
    assert out["period"] == "week"
    assert out["count"] == 4
    assert len(out["buckets"]) == 4
    assert "overall" in out
    assert "Run" in out["overall"]
    assert "Walk" in out["overall"]


# ---------- streams ----------

@pytest.mark.asyncio
@respx.mock
async def test_streams_passes_keys_through(fresh_client):
    route = respx.get("https://www.strava.com/api/v3/activities/77/streams").mock(
        return_value=httpx.Response(200, json={"heartrate": {"data": [120, 130, 140]}})
    )
    out = await tool_streams(
        fresh_client, activity_id=77, keys=["heartrate"], units=None
    )
    assert out["id"] == 77
    assert out["keys"] == ["heartrate"]
    assert out["streams"]["heartrate"]["data"] == [120, 130, 140]
    qs = str(route.calls.last.request.url)
    assert "keys=heartrate" in qs
    assert "key_by_type=true" in qs


# ---------- get_athlete ----------

@pytest.mark.asyncio
@respx.mock
async def test_get_athlete_includes_gear_with_converted_distance(fresh_client):
    respx.get("https://www.strava.com/api/v3/athlete").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": 12345,
                "firstname": "C",
                "lastname": "B",
                "sex": "M",
                "premium": True,
                "weight": 70.0,
                "ftp": 250,
                "bikes": [
                    {"id": "b1", "name": "Tarmac", "primary": True, "distance": 1609344.0},
                ],
                "shoes": [
                    {"id": "g1", "name": "Pegasus", "primary": True, "distance": 804672.0},
                ],
            },
        )
    )
    out = await tool_get_athlete(fresh_client, units="imperial")
    assert out["id"] == 12345
    assert out["ftp"] == 250
    assert out["weight"] == 70.0
    assert len(out["bikes"]) == 1
    bike = out["bikes"][0]
    # 1,609,344 m = 1000 mi
    assert bike["distance"] == pytest.approx(1000.0, abs=0.01)
    assert bike["distance_unit"] == "mi"
    # 804,672 m = 500 mi
    assert out["shoes"][0]["distance"] == pytest.approx(500.0, abs=0.01)


# ---------- athlete_zones ----------

@pytest.mark.asyncio
@respx.mock
async def test_athlete_zones_passes_through(fresh_client):
    payload = {
        "heart_rate": {
            "custom_zones": False,
            "zones": [
                {"min": 0, "max": 115},
                {"min": 115, "max": 152},
                {"min": 152, "max": 171},
                {"min": 171, "max": 190},
                {"min": 190, "max": -1},
            ],
        },
        "power": {"zones": [{"min": 0, "max": 180}]},
    }
    respx.get("https://www.strava.com/api/v3/athlete/zones").mock(
        return_value=httpx.Response(200, json=payload)
    )
    out = await tool_athlete_zones(fresh_client)
    assert out == payload


# ---------- activity_laps ----------

@pytest.mark.asyncio
@respx.mock
async def test_activity_laps_converts_units_and_computes_pace(fresh_client):
    respx.get("https://www.strava.com/api/v3/activities/55/laps").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "lap_index": 1,
                    "name": "Lap 1",
                    "split": 1,
                    "start_date_local": "2024-01-15T08:00:00Z",
                    "elapsed_time": 480,
                    "moving_time": 480,
                    "distance": 1609.344,  # 1 mi
                    "total_elevation_gain": 30.48,  # 100 ft
                    "average_speed": 3.35,  # ~7.5 mph
                    "max_speed": 5.0,
                    "average_heartrate": 150.0,
                    "max_heartrate": 165.0,
                    "average_cadence": 88.0,
                    "start_index": 0,
                    "end_index": 480,
                },
                {
                    "lap_index": 2,
                    "name": "Lap 2",
                    "split": 2,
                    "start_date_local": "2024-01-15T08:08:00Z",
                    "elapsed_time": 450,
                    "moving_time": 450,
                    "distance": 1609.344,
                    "total_elevation_gain": 0.0,
                    "average_speed": 3.575,
                    "start_index": 480,
                    "end_index": 930,
                },
            ],
        )
    )
    out = await tool_activity_laps(fresh_client, activity_id=55, units="imperial")
    assert out["id"] == 55
    assert out["count"] == 2
    assert out["units"] == "imperial"
    lap1, lap2 = out["laps"]
    assert lap1["distance"] == pytest.approx(1.0, abs=0.001)
    assert lap1["distance_unit"] == "mi"
    assert lap1["total_elevation_gain"] == pytest.approx(100.0, abs=0.5)
    assert lap1["elevation_unit"] == "ft"
    # 480 sec / 1 mi = 8:00/mi
    assert lap1["pace"] == "8:00/mi"
    # 5 m/s -> 11.18 mph
    assert lap1["max_speed"] == pytest.approx(11.185, abs=0.01)
    # passthrough fields preserved
    assert lap1["average_heartrate"] == 150.0
    assert lap1["average_cadence"] == 88.0
    assert lap1["start_index"] == 0
    assert lap1["end_index"] == 480
    # lap2 had no HR — that key should be absent, not None
    assert "average_heartrate" not in lap2


# ---------- activity_zones ----------

@pytest.mark.asyncio
@respx.mock
async def test_activity_zones_adds_totals_and_percents(fresh_client):
    respx.get("https://www.strava.com/api/v3/activities/55/zones").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "type": "heartrate",
                    "sensor_based": True,
                    "custom_zones": False,
                    "score": 42,
                    "points": 20,
                    "max": 190,
                    "distribution_buckets": [
                        {"min": 0, "max": 115, "time": 100},
                        {"min": 115, "max": 152, "time": 600},
                        {"min": 152, "max": 171, "time": 300},
                    ],
                }
            ],
        )
    )
    out = await tool_activity_zones(fresh_client, activity_id=55)
    assert out["id"] == 55
    assert out["count"] == 1
    z = out["zones"][0]
    assert z["type"] == "heartrate"
    assert z["total_time_sec"] == 1000
    assert z["score"] == 42
    # 600 / 1000 = 60.0%
    assert z["distribution_buckets"][1]["percent"] == 60.0
    assert z["distribution_buckets"][0]["time_sec"] == 100


@pytest.mark.asyncio
@respx.mock
async def test_activity_zones_handles_zero_total(fresh_client):
    """Empty zone (no time recorded) shouldn't divide-by-zero."""
    respx.get("https://www.strava.com/api/v3/activities/55/zones").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "type": "heartrate",
                    "distribution_buckets": [{"min": 0, "max": 115, "time": 0}],
                }
            ],
        )
    )
    out = await tool_activity_zones(fresh_client, activity_id=55)
    z = out["zones"][0]
    assert z["total_time_sec"] == 0
    assert z["distribution_buckets"][0]["percent"] == 0.0


# ---------- get_gear ----------

@pytest.mark.asyncio
@respx.mock
async def test_get_gear_converts_distance(fresh_client):
    respx.get("https://www.strava.com/api/v3/gear/b12345").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "b12345",
                "name": "Tarmac",
                "primary": True,
                "brand_name": "Specialized",
                "model_name": "Tarmac SL7",
                "frame_type": 3,
                "description": "Road bike",
                "distance": 1609344.0,  # 1000 mi
            },
        )
    )
    out = await tool_get_gear(fresh_client, gear_id="b12345", units="imperial")
    assert out["id"] == "b12345"
    assert out["brand_name"] == "Specialized"
    assert out["distance"] == pytest.approx(1000.0, abs=0.01)
    assert out["distance_unit"] == "mi"
    assert out["units"] == "imperial"


# ---------- ASGI dispatcher: OAuth-issued bearer tokens gate /mcp ----------

async def _ok_app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] == "http":
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"ok"})


def _make_app(tmp_path):
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    provider = OAuthProvider(store)
    import json as _json
    from strava_mcp.storage import TokenStore
    from strava_mcp.strava_oauth import StravaOAuthClient
    tp = tmp_path / "tokens.json"
    tp.write_text(_json.dumps({
        "client_id": "1", "client_secret": "shh",
        "refresh_token": "rt", "access_token": "at",
        "expires_at": 0, "units": "imperial",
    }))
    ts = TokenStore(tp)
    ts.load_or_seed()
    so = StravaOAuthClient(client_id="1", client_secret="shh")
    routes = make_oauth_routes(provider, token_store=ts, strava_oauth=so)
    app = StravaMCPApp(_ok_app, Starlette(routes=routes), provider)
    return app, provider


def _mint_token(provider: OAuthProvider) -> str:
    out = provider._issue_tokens(client_id="test", scope="mcp")
    return out["access_token"]


@pytest.mark.asyncio
async def test_unauth_mcp_returns_401(tmp_path):
    app, _ = _make_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/mcp")
        assert r.status_code == 401
        assert "Bearer" in r.headers.get("www-authenticate", "")


@pytest.mark.asyncio
async def test_garbage_bearer_returns_401(tmp_path):
    app, _ = _make_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/mcp", headers={"Authorization": "Bearer junk"})
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_valid_oauth_access_token_passes(tmp_path):
    app, provider = _make_app(tmp_path)
    token = _mint_token(provider)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/mcp", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.text == "ok"


@pytest.mark.asyncio
async def test_health_is_unauthenticated(tmp_path):
    app, _ = _make_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/health")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

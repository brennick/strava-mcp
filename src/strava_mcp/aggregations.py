"""Cardio rollups ported from build_dashboard.py's cardio_summary + weekly_cardio.

Generalized to:
  - support metric or imperial output (build_dashboard was imperial-only)
  - allow caller-chosen activity types (build_dashboard hardcoded Run/Walk)
  - bucket by week or month (build_dashboard only did weeks)
"""
from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

METERS_PER_MILE = 1609.344
METERS_PER_KM = 1000.0
METERS_PER_FOOT = 0.3048


def distance_value(meters: float, units: str) -> float:
    return meters / (METERS_PER_KM if units == "metric" else METERS_PER_MILE)


def elevation_value(meters: float, units: str) -> float:
    return meters if units == "metric" else meters / METERS_PER_FOOT


def speed_value(m_per_s: float, units: str) -> float:
    """m/s to mph (imperial) or km/h (metric)."""
    return m_per_s * 2.2369362920544 if units == "imperial" else m_per_s * 3.6


def distance_unit(units: str) -> str:
    return "km" if units == "metric" else "mi"


def elevation_unit(units: str) -> str:
    return "m" if units == "metric" else "ft"


def speed_unit(units: str) -> str:
    return "km/h" if units == "metric" else "mph"


def pace_str(seconds: float, distance: float, units: str) -> str:
    """Format pace as min/mi or min/km. Distance is in the chosen unit (mi or km)."""
    if seconds <= 0 or distance <= 0:
        return ""
    sp = seconds / distance
    m = int(sp // 60)
    ss = int(round(sp - m * 60))
    if ss == 60:
        m += 1
        ss = 0
    return f"{m}:{ss:02d}/{distance_unit(units)}"


def _activity_date(a: dict[str, Any]) -> date:
    s = a.get("start_date_local") or a.get("start_date") or ""
    s = s.replace("Z", "")
    return datetime.fromisoformat(s).date()


def _monday(d: date) -> date:
    return d - timedelta(days=d.weekday())


def _bucket_start(d: date, period: str) -> date:
    return _monday(d) if period == "week" else date(d.year, d.month, 1)


def _empty_bucket() -> dict[str, Any]:
    return {
        "distance": 0.0,
        "moving_time_sec": 0,
        "elevation_gain": 0.0,
        "count": 0,
    }


def cardio_summary(
    activities: list[dict[str, Any]],
    *,
    types: list[str] | None = None,
    units: str = "imperial",
) -> dict[str, dict[str, Any]]:
    """Mirror of build_dashboard.cardio_summary, generalized for type list + units.

    Returns {type: {distance, moving_time_sec, elevation_gain, count, pace}}.
    """
    types = list(types) if types else ["Run", "Walk"]
    out = {t: _empty_bucket() for t in types}
    for a in activities:
        t = a.get("type")
        if t not in out:
            continue
        out[t]["distance"] += distance_value(a.get("distance", 0) or 0, units)
        out[t]["moving_time_sec"] += int(a.get("moving_time", 0) or 0)
        out[t]["elevation_gain"] += elevation_value(a.get("total_elevation_gain", 0) or 0, units)
        out[t]["count"] += 1
    for t, v in out.items():
        v["pace"] = pace_str(v["moving_time_sec"], v["distance"], units)
        v["distance"] = round(v["distance"], 3)
        v["elevation_gain"] = round(v["elevation_gain"], 1)
    return out


def _generate_starts(period: str, count: int, today: date) -> list[date]:
    if period == "week":
        anchor = _monday(today)
        return [anchor - timedelta(days=7 * i) for i in range(count - 1, -1, -1)]
    # month
    starts: list[date] = []
    y, m = today.year, today.month
    for _ in range(count):
        starts.append(date(y, m, 1))
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    starts.reverse()
    return starts


def bucketed(
    activities: list[dict[str, Any]],
    *,
    period: str,
    count: int,
    types: list[str] | None = None,
    units: str = "imperial",
    today: date | None = None,
) -> list[dict[str, Any]]:
    """Roll activities into `count` week- or month-buckets ending at `today`.

    Each bucket: {start, by_type: {Run: {...}, Walk: {...}}, totals: {...}}.
    """
    if period not in ("week", "month"):
        raise ValueError(f"period must be 'week' or 'month', got {period!r}")
    types = list(types) if types else ["Run", "Walk"]
    today = today or date.today()

    starts = _generate_starts(period, count, today)
    by_start: dict[date, dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    for s in starts:
        bucket = {
            "start": s.isoformat(),
            "by_type": {t: _empty_bucket() for t in types},
            "totals": _empty_bucket(),
        }
        out.append(bucket)
        by_start[s] = bucket

    for a in activities:
        t = a.get("type")
        if t not in types:
            continue
        s = _bucket_start(_activity_date(a), period)
        bucket = by_start.get(s)
        if not bucket:
            continue
        d = distance_value(a.get("distance", 0) or 0, units)
        mt = int(a.get("moving_time", 0) or 0)
        el = elevation_value(a.get("total_elevation_gain", 0) or 0, units)
        for target in (bucket["by_type"][t], bucket["totals"]):
            target["distance"] += d
            target["moving_time_sec"] += mt
            target["elevation_gain"] += el
            target["count"] += 1

    for bucket in out:
        for t, v in bucket["by_type"].items():
            v["pace"] = pace_str(v["moving_time_sec"], v["distance"], units)
            v["distance"] = round(v["distance"], 3)
            v["elevation_gain"] = round(v["elevation_gain"], 1)
        tot = bucket["totals"]
        tot["pace"] = pace_str(tot["moving_time_sec"], tot["distance"], units)
        tot["distance"] = round(tot["distance"], 3)
        tot["elevation_gain"] = round(tot["elevation_gain"], 1)
    return out


def trim_activity(a: dict[str, Any], units: str) -> dict[str, Any]:
    """Trimmed activity shape used by list_activities."""
    out: dict[str, Any] = {
        "id": a.get("id"),
        "type": a.get("type"),
        "name": a.get("name", ""),
        "start_date_local": a.get("start_date_local") or a.get("start_date", ""),
        "distance": round(distance_value(a.get("distance", 0) or 0, units), 3),
        "moving_time_sec": int(a.get("moving_time", 0) or 0),
        "elapsed_time_sec": int(a.get("elapsed_time", 0) or 0),
        "total_elevation_gain": round(elevation_value(a.get("total_elevation_gain", 0) or 0, units), 1),
        "average_speed": round(speed_value(a.get("average_speed", 0) or 0, units), 3),
        "distance_unit": distance_unit(units),
        "elevation_unit": elevation_unit(units),
        "speed_unit": speed_unit(units),
    }
    if a.get("average_heartrate") is not None:
        out["average_heartrate"] = a["average_heartrate"]
    if a.get("max_heartrate") is not None:
        out["max_heartrate"] = a["max_heartrate"]
    return out

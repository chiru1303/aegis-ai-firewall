"""
Aegis AI Firewall - Centralized Time & Indian Standard Time (IST) Module
All timestamps throughout Aegis use Indian Standard Time (UTC+05:30) and DD/MM/YYYY formatting.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Union

# Indian Standard Timezone (UTC+05:30)
IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def now_utc() -> datetime:
    """Return the current datetime in UTC (internal storage standard)."""
    return datetime.now(timezone.utc)


def now_ist() -> datetime:
    """Return the current datetime in Indian Standard Time (IST)."""
    return datetime.now(timezone.utc).astimezone(IST)


def now_ist_iso() -> str:
    """Return current IST datetime formatted as ISO 8601 with +05:30 offset."""
    return now_ist().isoformat()


def to_ist(val: Union[datetime, str, float, int, None]) -> Optional[datetime]:
    """Convert any datetime, ISO string, or timestamp into an IST-aware datetime object."""
    if val is None or val == "":
        return None

    if isinstance(val, (int, float)):
        # Epoch timestamp
        epoch = val if val < 1e11 else val / 1000.0
        return datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone(IST)

    if isinstance(val, str):
        # Handle string formats
        s = val.strip()
        # If already formatted with dd/mm/yyyy
        if "/" in s and "IST" in s:
            try:
                # Try parsing dd/mm/yyyy HH:MM:SS IST
                clean_s = s.replace(" IST", "")
                parts = clean_s.split(" ")
                d, m, y = parts[0].split("/")
                time_part = parts[1] if len(parts) > 1 else "00:00:00"
                h, mi, sec = (time_part.split(":") + ["00"])[:3]
                return datetime(int(y), int(m), int(d), int(h), int(mi), int(float(sec)), tzinfo=IST)
            except Exception:
                pass

        try:
            # Try ISO format
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(IST)
        except Exception:
            try:
                # Common SQL format "YYYY-MM-DD HH:MM:SS"
                dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc).astimezone(IST)
            except Exception:
                return None

    if isinstance(val, datetime):
        if val.tzinfo is None:
            # Naive datetime from SQLite is assumed to be stored in UTC
            val = val.replace(tzinfo=timezone.utc)
        return val.astimezone(IST)

    return None


def format_ist(
    val: Union[datetime, str, float, int, None],
    include_time: bool = True,
    include_seconds: bool = True,
    show_tz_label: bool = True,
) -> str:
    """
    Format any date value to DD/MM/YYYY and Indian Standard Time (IST).
    Examples:
      - format_ist(dt) -> "01/10/2026 15:25:30 IST"
      - format_ist(dt, include_seconds=False) -> "01/10/2026 15:25 IST"
      - format_ist(dt, include_time=False) -> "01/10/2026"
    """
    dt = to_ist(val)
    if dt is None:
        return str(val) if val else ""

    tz_suffix = " IST" if show_tz_label else ""
    if not include_time:
        return dt.strftime("%d/%m/%Y")

    if include_seconds:
        return dt.strftime(f"%d/%m/%Y %H:%M:%S{tz_suffix}")
    return dt.strftime(f"%d/%m/%Y %H:%M{tz_suffix}")

"""Time helper — all timestamps in UTC.

Every timestamp the tool records or displays uses UTC.
`now_utc()` returns a timezone-aware datetime pinned to UTC.
`now_local()` is kept as an alias for callers that haven't been updated yet.
"""
from __future__ import annotations

from datetime import datetime, timezone


def now_utc() -> datetime:
    """Timezone-aware 'now' in UTC."""
    return datetime.now(timezone.utc)


def now_local() -> datetime:
    """Legacy alias — returns UTC."""
    return now_utc()

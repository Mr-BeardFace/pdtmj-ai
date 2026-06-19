"""Local-time helper.

The engagement records and displays timestamps in the LOCAL timezone of whoever
runs the tool (an operator reading a report wants their own wall-clock, not UTC).
`now_local()` returns a timezone-AWARE datetime in the local zone, so it still
serialises with an explicit offset and subtracts cleanly against other aware
datetimes — we just stop pinning everything to UTC.

Note: certificate validity in tools/tls_inspect.py stays UTC on purpose — x.509
notBefore/notAfter are defined in UTC and must not be localised.
"""
from __future__ import annotations

from datetime import datetime


def now_local() -> datetime:
    """Timezone-aware 'now' in the local timezone of the host running the tool."""
    return datetime.now().astimezone()

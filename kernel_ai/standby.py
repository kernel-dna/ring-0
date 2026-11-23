"""Standby role for the copy that takes traffic only when the primary is down.

The ALB uses one health check for every target. The primary answers 200
whenever it can. The standby answers 503 while the primary still answers, so
the balancer sends it nothing, and 200 once the primary stops answering.
"""

from __future__ import annotations

import os
import ssl
import urllib.request

_DISABLED = {"0", "false", "no", "off"}


def ml_enabled() -> bool:
    """False on the visualization-only copy. The ML worker is a separate unit
    and is simply not installed there; this flag keeps the read APIs from
    treating the primary's stored rows as this machine's detector."""
    return os.getenv("KERNEL_AI_ML_ENABLED", "true").strip().lower() not in _DISABLED


def standby_peer() -> str:
    return os.getenv("KERNEL_AI_STANDBY_PEER", "").strip()


def peer_is_up(url: str, timeout: float = 2.0) -> bool:
    """True when the peer completes an HTTP response below 400.

    A hung guest does not complete the handshake, which lands in the except
    and is reported as down. A redirect that resolves to a successful page
    counts as up.
    """
    if not url:
        return False
    request = urllib.request.Request(
        url,
        headers={"Host": os.getenv("KERNEL_AI_STANDBY_PEER_HOST", "ring-0.sh")},
        method="GET",
    )
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=ssl._create_unverified_context()
        ) as response:
            return 200 <= int(response.status) < 400
    except Exception:
        return False

"""Bounded, user-initiated unified-log observation without OS file inspection."""
from datetime import datetime, timezone
import os


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def acquire_mac(scan_id, limits, *, check=None):
    from .discovery import host_epoch
    from .system_logs import acquire_logs
    epoch = host_epoch()
    source = acquire_logs(epoch, limits, check=check)
    return {"host_epoch_id": epoch, "scan_id": scan_id,
            "acquisition": source["acquisition"], "sources": [source],
            "self_activity": {"pid": os.getpid(), "kind": "mac_log_acquisition"}}

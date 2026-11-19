"""Collect a bounded live window of selected macOS security log events."""

from datetime import datetime, timezone
import hashlib
import json
import re

from mn_macos_logs_skill import observe_unified_logs
from mn_temporal_graph_skill import fingerprint

from .acquisition import now
from .log_signals import MESSAGE_FRAGMENTS, PROCESSES, signal_for


_REVIEW_MESSAGE_TYPES = ("fault",)
_LEVELS = {"Default", "Info", "Error", "Fault"}
_METADATA = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


def _timestamp(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError("log event time lacks a timezone")
    return stamp


def _record(line, epoch, start, end):
    value = json.loads(line)
    stamp = _timestamp(value["timestamp"])
    if not start <= stamp <= end:
        raise ValueError("log event is outside this observation window")
    image = value["processImagePath"]
    process = image.rsplit("/", 1)[-1]
    if process not in PROCESSES:
        raise ValueError("log event is outside the selected process scope")
    timestamp = stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    fields = {"process": process, "log_record_sha256": hashlib.sha256(line).hexdigest()}
    for key in ("subsystem", "category"):
        if isinstance(value.get(key), str) and _METADATA.fullmatch(value[key]):
            fields[key] = value[key]
    level = value.get("messageType")
    if isinstance(level, str) and level in _LEVELS:
        fields["messageType"] = level
    signal = signal_for(image, value.get("eventMessage"), level)
    if signal:
        fields["signal"], fields["indicator"] = signal
    return {
        "kind": "event",
        "entity": "logger-" + fingerprint([epoch, process]),
        "capability": "diagnostic_event",
        "claim_class": "observed",
        "fields": fields,
        "time": {"earliest": timestamp, "latest": timestamp},
    }


def acquire_logs(epoch, limits, *, check=None):
    started = now()
    result = observe_unified_logs(
        processes=PROCESSES,
        duration_seconds=limits["observation_seconds"],
        max_bytes=limits["max_log_bytes"],
        message_contains=MESSAGE_FRAGMENTS,
        message_types=_REVIEW_MESSAGE_TYPES,
        check=check,
    )
    ended = now()
    start, end = _timestamp(started), _timestamp(ended)
    records, digests = [], set()
    gaps = list(result["gaps"])
    if end < start:
        gaps.append("clock_changed")
    for line in result["data"].split(b"\n"):
        if not line.strip():
            continue
        if check is not None:
            check()
        try:
            record = _record(line, epoch, start, end)
        except (KeyError, ValueError, TypeError, AttributeError, RecursionError):
            gaps.append("unparsed_or_out_of_scope_record")
            continue
        digest = record["fields"]["log_record_sha256"]
        if digest in digests:
            continue
        if len(records) >= limits["max_log_records"]:
            gaps.append("record_limit")
            break
        records.append(record)
        digests.add(digest)
    enumeration = result["enumeration"]
    if result["availability"] == "available" and gaps:
        enumeration = "partial"
    return {
        "source_id": "unified-security-log",
        "source_name": "macOS unified log stream",
        "scope": "system",
        "requested_path": "macOS unified log stream",
        "collection_mode": "live",
        "parser_version": "unified-log-stream-v1",
        "capabilities": ["diagnostic_event"],
        "consistency": "non_atomic",
        "acquisition": {"earliest": started, "latest": ended if end >= start else None},
        "requested_duration_seconds": limits["observation_seconds"],
        "processes": list(PROCESSES),
        "filter": {"message_fragments": list(MESSAGE_FRAGMENTS), "message_types": list(_REVIEW_MESSAGE_TYPES)},
        "availability": result["availability"],
        "enumeration": enumeration,
        "records": records,
        "gaps": list(dict.fromkeys(gaps)),
    }

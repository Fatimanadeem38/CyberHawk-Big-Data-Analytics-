"""
Validates and normalises log records coming from uploaded CSV / JSON files
into the project's event schema, before they are published to Kafka.

Used by:  scripts/ingest_file.py  and  the Django upload API.

Accepted column names (case-insensitive). Several aliases are accepted so
that common public datasets (for example UNSW-NB15 style columns such as
srcip / dstip / sport / dsport / proto / dur / sbytes / spkts / stime) can
be loaded without editing the file.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import uuid
from datetime import datetime, timezone

ALIASES = {
    "event_id": ["event_id", "id", "eventid", "uid"],
    "timestamp": ["timestamp", "time", "stime", "datetime", "date_time", "@timestamp", "ts"],
    "src_ip": ["src_ip", "source_ip", "srcip", "source ip", "src", "saddr"],
    "dst_ip": ["dst_ip", "destination_ip", "dstip", "destination ip", "dst", "daddr"],
    "src_port": ["src_port", "source_port", "sport", "source port"],
    "dst_port": ["dst_port", "destination_port", "dsport", "dport", "destination port"],
    "protocol": ["protocol", "proto"],
    "packet_size": ["packet_size", "bytes", "sbytes", "packet_length", "size"],
    "duration": ["duration", "dur", "flow duration", "connection_duration"],
    "request_count": ["request_count", "requests", "spkts", "packets", "count"],
    "failed_logins": ["failed_logins", "failed_login_attempts", "num_failed_logins"],
    "event_type": ["event_type", "type", "service", "action"],
    "network_status": ["network_status", "status", "state"],
    "log_source": ["log_source", "source_type", "log_type"],
    "username": ["username", "user", "account"],
    "true_label": ["true_label", "label", "attack_cat", "class"],
    "is_simulated": ["is_simulated", "simulated"],
}
VALID_SOURCES = {"network", "firewall", "authentication", "server_access", "ids"}
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
MAX_ROWS = 50000


def _lookup(record: dict, field: str):
    lowered = {str(k).strip().lower(): v for k, v in record.items()}
    for alias in ALIASES[field]:
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None


def _to_int(v, default=0, lo=0, hi=None):
    try:
        x = int(float(v))
    except (TypeError, ValueError):
        return default
    if x < lo:
        return default
    if hi is not None and x > hi:
        return default
    return x


def _to_float(v, default=0.0):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return default
    return x if x >= 0 else default


def parse_timestamp(v) -> datetime | None:
    if v in (None, ""):
        return None
    s = str(v).strip()
    try:  # epoch seconds or milliseconds
        num = float(s)
        if num > 1e12:
            num /= 1000.0
        return datetime.fromtimestamp(num, tz=timezone.utc)
    except ValueError:
        pass
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00")) if fmt is None else datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _valid_ip(v) -> str | None:
    try:
        ip = ipaddress.ip_address(str(v).strip())
        return str(ip) if ip.version == 4 else None
    except ValueError:
        return None


def normalize_record(raw: dict, default_source: str = "network") -> tuple[dict | None, str]:
    """Returns (event, "") when valid or (None, reason) when the row is rejected."""
    src_ip = _valid_ip(_lookup(raw, "src_ip"))
    dst_ip = _valid_ip(_lookup(raw, "dst_ip"))
    if not src_ip or not dst_ip:
        return None, "invalid or missing source/destination IPv4 address"

    ts = parse_timestamp(_lookup(raw, "timestamp")) or datetime.now(timezone.utc)
    proto = str(_lookup(raw, "protocol") or "TCP").strip().upper()
    if proto not in VALID_PROTOCOLS:
        proto = "OTHER"
    source = str(_lookup(raw, "log_source") or default_source).strip().lower()
    if source not in VALID_SOURCES:
        source = default_source
    sim = str(_lookup(raw, "is_simulated") or "").strip().lower() in ("1", "true", "yes")
    label = str(_lookup(raw, "true_label") or "").strip().lower().replace(" ", "_")
    if label in ("0", "benign"):
        label = "normal"

    event = {
        "event_id": str(_lookup(raw, "event_id") or ""),
        "timestamp": _iso(ts),
        "log_source": source,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": _to_int(_lookup(raw, "src_port"), 0, 0, 65535),
        "dst_port": _to_int(_lookup(raw, "dst_port"), 0, 0, 65535),
        "protocol": proto,
        "packet_size": _to_int(_lookup(raw, "packet_size"), 0),
        "duration": round(_to_float(_lookup(raw, "duration")), 3),
        "request_count": max(1, _to_int(_lookup(raw, "request_count"), 1)),
        "failed_logins": _to_int(_lookup(raw, "failed_logins"), 0),
        "event_type": str(_lookup(raw, "event_type") or "imported_event")[:64],
        "network_status": str(_lookup(raw, "network_status") or "unknown")[:32],
        "username": str(_lookup(raw, "username") or "")[:64],
        "is_simulated": sim,
        "scenario": "uploaded_file",
        "true_label": label,
    }
    if not event["event_id"]:
        # deterministic id -> uploading the same file twice does not create duplicates
        basis = json.dumps(raw, sort_keys=True, default=str)
        event["event_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, basis))
    return event, ""


def read_records(content: bytes, filename: str) -> list[dict]:
    """Reads CSV, JSON array or JSON-lines content into a list of dicts."""
    text = content.decode("utf-8-sig", errors="replace")
    name = filename.lower()
    if name.endswith(".csv"):
        return list(csv.DictReader(io.StringIO(text)))[:MAX_ROWS]
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(stripped)
        return [r for r in data if isinstance(r, dict)][:MAX_ROWS]
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except json.JSONDecodeError:
                rows.append({"__invalid__": line})
        if len(rows) >= MAX_ROWS:
            break
    return rows


def replay_as_now(events: list[dict]) -> None:
    """Shift timestamps so the newest event becomes 'now' (keeps the gaps)."""
    stamps = [parse_timestamp(e["timestamp"]) for e in events]
    if not stamps:
        return
    shift = datetime.now(timezone.utc) - max(stamps)
    for e, dt in zip(events, stamps):
        e["timestamp"] = _iso(dt + shift)

"""
Elasticsearch helper used by every API. Elasticsearch is the main
searchable store for security events, detections and alerts.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from django.conf import settings
from elasticsearch import ApiError, Elasticsearch, NotFoundError, TransportError

log = logging.getLogger(__name__)

EVENTS = "security-events"
DETECTIONS = "threat-detections"
ALERTS = "security-alerts"
MODEL_METRICS = "model-metrics"
PIPELINE = "pipeline-metrics"

RANGES = {"15m": "now-15m", "1h": "now-1h", "6h": "now-6h", "24h": "now-24h",
          "7d": "now-7d", "30d": "now-30d", "all": None}
INTERVALS = {"15m": "30s", "1h": "1m", "6h": "5m", "24h": "30m", "7d": "3h", "30d": "12h", "all": "1d"}

_client: Elasticsearch | None = None


class ESUnavailable(Exception):
    """Raised when Elasticsearch cannot be reached (shown as HTTP 503)."""


def client() -> Elasticsearch:
    global _client
    if _client is None:
        _client = Elasticsearch(settings.ELASTICSEARCH_URL, request_timeout=10,
                                retry_on_timeout=True, max_retries=2)
    return _client


def search(index: str, **body) -> dict:
    try:
        return client().search(index=index, **body).body
    except NotFoundError:
        return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}
    except (TransportError, ApiError, ConnectionError) as exc:
        log.warning("Elasticsearch search failed on %s: %s", index, exc)
        raise ESUnavailable(str(exc)) from exc


def count(index: str, query: dict | None = None) -> int:
    try:
        return int(client().count(index=index, query=query or {"match_all": {}})["count"])
    except NotFoundError:
        return 0
    except (TransportError, ApiError, ConnectionError) as exc:
        raise ESUnavailable(str(exc)) from exc


def get(index: str, doc_id: str) -> dict | None:
    try:
        r = client().get(index=index, id=doc_id)
        return {**r["_source"], "_id": r["_id"]}
    except NotFoundError:
        return None
    except (TransportError, ApiError, ConnectionError) as exc:
        raise ESUnavailable(str(exc)) from exc


def update(index: str, doc_id: str, doc: dict) -> None:
    try:
        client().update(index=index, id=doc_id, doc=doc, refresh="wait_for", retry_on_conflict=3)
    except (TransportError, ApiError, ConnectionError) as exc:
        raise ESUnavailable(str(exc)) from exc


def hits(resp: dict) -> list[dict]:
    return [{**h["_source"], "_id": h["_id"]} for h in resp.get("hits", {}).get("hits", [])]


def total(resp: dict) -> int:
    t = resp.get("hits", {}).get("total", 0)
    return int(t["value"] if isinstance(t, dict) else t)


def buckets(resp: dict, name: str) -> list[dict]:
    return resp.get("aggregations", {}).get(name, {}).get("buckets", [])


def range_filter(field: str, range_key: str | None) -> list[dict]:
    start = RANGES.get(range_key or "24h", "now-24h")
    return [{"range": {field: {"gte": start}}}] if start else []


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

"""
Real-time WebSocket:  ws://localhost:8000/ws/stream/

Data path: Kafka -> Spark -> Elasticsearch -> (this consumer) -> browser.
Every REALTIME_POLL_SECONDS the consumer asks Elasticsearch for events
and alerts that are newer than what this browser has already received,
and pushes them. Every third cycle it also pushes fresh dashboard KPIs.

Messages sent to the browser:
  {"type": "hello"}                         connection accepted
  {"type": "events", "items": [...]}        new processed security events
  {"type": "alerts", "items": [...]}        new or updated alerts
  {"type": "stats",  "data": {...}}         dashboard numbers
  {"type": "error",  "service": "...", "detail": "..."}
"""
import asyncio
import logging
from collections import deque

from asgiref.sync import sync_to_async
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.conf import settings

from core import es
from core.permissions import user_role

from .services import dashboard_stats

log = logging.getLogger(__name__)
CONNECTED = {"count": 0}

EVENT_FIELDS = ["event_id", "event_time", "processed_at", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "event_type", "log_source", "predicted_class", "ml_probability",
                "anomaly_score", "is_anomaly", "threat_category", "severity", "is_threat",
                "is_simulated", "bytes_total", "alert_id", "network_status"]


class _Seen:
    def __init__(self, size=5000):
        self.q, self.s = deque(), set()
        self.size = size

    def add(self, key) -> bool:
        if key in self.s:
            return False
        self.q.append(key)
        self.s.add(key)
        if len(self.q) > self.size:
            self.s.discard(self.q.popleft())
        return True


class StreamConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        role = await database_sync_to_async(user_role)(user)
        if role not in ("admin", "analyst"):
            await self.close(code=4403)
            return
        await self.accept()
        CONNECTED["count"] += 1
        self.event_cursor = self.alert_cursor = es.utc_now_iso()
        self.seen_events, self.seen_alerts = _Seen(), _Seen(2000)
        self.es_ok = True
        self.task = asyncio.create_task(self._loop())
        await self.send_json({"type": "hello", "poll_seconds": settings.REALTIME_POLL_SECONDS})

    async def disconnect(self, code):
        task = getattr(self, "task", None)
        if task:
            task.cancel()
            CONNECTED["count"] = max(0, CONNECTED["count"] - 1)

    async def receive_json(self, content, **kwargs):
        if content.get("type") == "ping":
            await self.send_json({"type": "pong"})

    # ------------------------------------------------------------------
    async def _loop(self):
        cycle = 0
        while True:
            try:
                events = await sync_to_async(self._new_events, thread_sensitive=False)()
                if events:
                    await self.send_json({"type": "events", "items": events})
                alerts = await sync_to_async(self._new_alerts, thread_sensitive=False)()
                if alerts:
                    await self.send_json({"type": "alerts", "items": alerts})
                if cycle % 3 == 0:
                    stats = await sync_to_async(dashboard_stats, thread_sensitive=False)("24h", True)
                    await self.send_json({"type": "stats", "data": stats})
                if not self.es_ok:
                    self.es_ok = True
                    await self.send_json({"type": "recovered", "service": "elasticsearch"})
            except asyncio.CancelledError:
                raise
            except es.ESUnavailable as exc:
                if self.es_ok:
                    await self.send_json({"type": "error", "service": "elasticsearch", "detail": str(exc)[:200]})
                self.es_ok = False
            except Exception as exc:  # keep the socket alive
                log.exception("realtime loop error")
                await self.send_json({"type": "error", "service": "backend", "detail": str(exc)[:200]})
            cycle += 1
            await asyncio.sleep(settings.REALTIME_POLL_SECONDS)

    def _new_events(self):
        # All events of one Spark micro-batch share the same processed_at value,
        # so we query with "gte" and drop the ones this socket has already sent.
        resp = es.search(es.EVENTS, size=300, sort=[{"processed_at": "desc"}], source=EVENT_FIELDS,
                         query={"range": {"processed_at": {"gte": self.event_cursor}}})
        out = [h for h in es.hits(resp) if self.seen_events.add(h["_id"])]
        if out:
            self.event_cursor = max(h.get("processed_at", self.event_cursor) for h in out)
        return out

    def _new_alerts(self):
        resp = es.search(es.ALERTS, size=50, sort=[{"updated_at": "desc"}],
                         query={"range": {"updated_at": {"gte": self.alert_cursor}}})
        out = [h for h in es.hits(resp) if self.seen_alerts.add(f"{h['_id']}|{h.get('updated_at')}|{h.get('status')}")]
        if out:
            self.alert_cursor = max(h.get("updated_at", self.alert_cursor) for h in out)
        return out

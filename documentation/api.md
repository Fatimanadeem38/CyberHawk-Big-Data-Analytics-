# REST API reference

All APIs need a signed-in session (cookie) with the **Security Analyst** or **Administrator** role, unless noted. Write requests need the `X-CSRFToken` header (the frontend adds it). The example responses show the **structure**. The values are only illustrations.

Errors: `400` validation, `403` no permission, `404` not found, `503` Elasticsearch not reachable (`{"detail": "...", "service": "elasticsearch"}`).

## Dashboard
`GET /api/dashboard/stats/?range=1h|6h|24h|7d|30d|all`
```json
{
  "range": "24h", "total_events_all_time": 48211, "events_in_range": 40310,
  "threat_events": 2210, "normal_events": 37950, "anomaly_events": 1630,
  "anomaly_rate": 4.04, "threat_rate": 5.48, "traffic_bytes": 9123456789,
  "alerts_in_range": 41, "open_alerts": 30, "critical_alerts": 3, "high_alerts": 12,
  "timeline": [{"t": "2026-11-16T15:01:00.000Z", "events": 480, "threats": 12, "bytes": 1203345}],
  "threat_distribution": [{"key": "dos", "count": 900}],
  "severity_distribution": [{"key": "high", "count": 20}],
  "recent_alerts": [{"_id": "9f3c…", "severity": "high", "threat_category": "brute_force", "src_ip": "203.0.113.7", "event_count": 64, "status": "new"}]
}
```

## Security events (Elasticsearch `security-events`)
| Method & URL | Purpose |
|---|---|
| `GET /api/events/recent/?size=100&q=&protocol=&severity=&predicted_class=&threats_only=1` | newest processed events |
| `GET /api/events/search/?q=&src_ip=&dst_ip=&protocol=&log_source=&threat_category=&severity=&date_from=&date_to=&range=&threats_only=&page=&size=&sort=&order=` | historical search (IP or CIDR) |
| `GET /api/events/export/?…same filters…` | CSV download (max 10,000 rows, audited) |
| `GET /api/events/by-ip/<ip>/` | IP profile: counts, top peers/ports, categories, alerts |
| `GET /api/events/<event_id>/` | one event |

## Threat detection
| | |
|---|---|
| `GET /api/detections/?range=&threat_category=&severity=&method=ml_random_forest\|anomaly_kmeans\|rule:&q=&page=` | detected threats + facets |
| `GET /api/detections/<event_id>/` | detection + its alert |
| `GET /api/models/metrics/` | `offline` (test-set metrics per model), `live` (last-24 h statistics), `training_history` |

## Alerts
| | |
|---|---|
| `GET /api/alerts/?status=&severity=&threat_category=&q=<ip>&range=7d&sort=last_seen\|severity_rank\|event_count&page=` | list + status/severity counts |
| `GET /api/alerts/<alert_id>/` | alert, workflow, notes, related events, history, other alerts from the same source |
| `PATCH /api/alerts/<alert_id>/status/` body `{"status": "investigating\|resolved\|false_positive\|new", "note": "...", "assign_to_me": true, "resolution_summary": "..."}` | change the workflow |
| `GET/POST /api/alerts/<alert_id>/notes/` body `{"text": "..."}` | investigation notes |

Example `PATCH` response: `{"alert_id": "9f3c…", "status": "resolved", "assigned_to": "analyst"}`

## Analytics
`GET /api/analytics/overview/?range=24h` → `traffic_over_time`, `protocols`, `log_sources`, `top_sources`, `top_destinations`, `top_ports`, `network_status`, `suspicious_trend {labels, series{category:[…]}}`, `unique_sources`, `total_bytes`.

## System monitoring
| | |
|---|---|
| `GET /api/system/health/` | `{"overall": "up\|degraded\|down", "components": [{"name": "Kafka", "status": "up", "message": "...", "details": {...}}, …]}`. Live checks of Kafka, Spark, HDFS, Elasticsearch, MongoDB, Django and the generator |
| `GET /api/system/pipeline/` | recent Spark batch and progress metrics |
| `GET /api/system/audit/` | audit log (**Administrator**) |

## Log ingestion
| | |
|---|---|
| `GET /api/ingestion/status/` | switch, generator heartbeat, Kafka topic counters, recent scenario requests and uploads |
| `POST /api/ingestion/control/` body `{"enabled": true, "rate": 8, "attack_probability": 0.02}` | **Administrator** |
| `POST /api/ingestion/scenario/` body `{"scenario": "brute_force"}` | **Administrator**. Scenarios: `brute_force, port_scan, dos, suspicious_frequency, unusual_volume, abnormal_auth` |
| `POST /api/ingestion/upload/` multipart: `file`, `default_source`, `replay_now` | **Administrator** |
| `GET /api/ingestion/service/control/`, `POST /api/ingestion/service/heartbeat/` | for the generator, header `X-Service-Token` |

Example upload response:
```json
{"filename": "sample_logs.csv", "rows_total": 1541, "rows_valid": 1541, "rows_rejected": 0,
 "rows_published": 1541, "rejection_reasons": {}, "status": "completed"}
```

## Accounts
`GET /api/accounts/me/` → `{"username": "admin", "role": "admin", ...}` · `/login/` · `POST /logout/` · `/admin/` (Django admin for users and groups)

## WebSocket
`ws://localhost:8000/ws/stream/` (session cookie). Server messages: `hello`, `events {items}`, `alerts {items}`, `stats {data}`, `error {service, detail}`, `recovered`, `pong`. Client message: `{"type": "ping"}`.

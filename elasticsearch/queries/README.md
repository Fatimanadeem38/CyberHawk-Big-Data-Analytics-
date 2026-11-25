# Example Elasticsearch queries

These are the same kinds of queries that the Django APIs send (see `backend/*/views.py`).

| File | Endpoint / note |
|---|---|
| `filter_severity_category_date.json` | GET threat-detections/_search |
| `recent_alerts.json` | GET security-alerts/_search |
| `search_by_source_ip.json` | GET security-events/_search |
| `search_by_subnet.json` | CIDR search works because src_ip/dst_ip are 'ip' fields |
| `threat_statistics.json` | GET threat-detections/_search  (dashboard aggregation) |
| `traffic_analytics.json` | GET security-events/_search |

Try one from the WSL terminal in the project folder:

```bash
curl -s -H 'Content-Type: application/json' -X GET \
  'http://localhost:9200/security-events/_search?pretty' \
  -d @elasticsearch/queries/search_by_source_ip.json
```

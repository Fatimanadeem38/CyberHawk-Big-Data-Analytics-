"""Builds Elasticsearch queries from the search/filter parameters of the UI."""
import ipaddress

from core import es

FILTER_TERMS = {
    "protocol": "protocol", "log_source": "log_source", "event_type": "event_type",
    "predicted_class": "predicted_class", "severity": "severity", "threat_category": "threat_category",
    "network_status": "network_status",
}


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def ip_clause(value: str, fields=("src_ip", "dst_ip")):
    """Exact IP or CIDR (e.g. 10.0.1.0/24) on source or destination."""
    value = value.strip()
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
    elif not _is_ip(value):
        return None
    return {"bool": {"should": [{"term": {f: value}} for f in fields], "minimum_should_match": 1}}


def build_event_query(params, time_field: str = "event_time", default_range: str | None = None) -> dict:
    """Supported params: q (IP or text), src_ip, dst_ip, protocol, log_source, event_type,
    predicted_class, severity, threat_category, threats_only, simulated, date_from, date_to, range."""
    must, filters = [], []
    q = (params.get("q") or "").strip()
    if q:
        clause = ip_clause(q)
        if clause:
            filters.append(clause)
        else:
            text_fields = ["event_type", "username", "scenario", "threat_category", "predicted_class",
                           "log_source", "network_status", "event_id", "protocol"]
            must.append({"bool": {"should": [{"prefix": {f: {"value": q, "case_insensitive": True}}}
                                             for f in text_fields], "minimum_should_match": 1}})
    for name in ("src_ip", "dst_ip"):
        v = (params.get(name) or "").strip()
        if v:
            c = ip_clause(v, fields=(name,))
            filters.append(c if c else {"term": {name: "0.0.0.0"}})
    for param, field in FILTER_TERMS.items():
        v = (params.get(param) or "").strip()
        if v:
            filters.append({"terms": {field: [x for x in v.split(",") if x]}})
    if params.get("threats_only") in ("1", "true", "yes"):
        filters.append({"term": {"is_threat": True}})
    if params.get("simulated") in ("0", "1"):
        filters.append({"term": {"is_simulated": params.get("simulated") == "1"}})
    date_from, date_to = params.get("date_from"), params.get("date_to")
    if date_from or date_to:
        rng = {}
        if date_from:
            rng["gte"] = date_from
        if date_to:
            rng["lte"] = date_to
        filters.append({"range": {time_field: rng}})
    else:
        filters += es.range_filter(time_field, params.get("range") or default_range or "all")
    return {"bool": {"must": must or [{"match_all": {}}], "filter": filters}}

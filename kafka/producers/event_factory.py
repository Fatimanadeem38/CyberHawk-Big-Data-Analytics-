"""
Simulated security event factory.
=================================

IMPORTANT: every event created here is SIMULATED data for testing and
training. Each event carries ``is_simulated = True`` and a ground-truth
``true_label``. They do not represent real attacks.

External (internet) addresses use the reserved documentation ranges
192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737), so no real
public host is ever named. Internal hosts use 10.0.0.0/8.

This module is pure Python (no Kafka, no Spark), so the same code is used by:
  * scripts/generate_logs.py          -> live stream into Kafka
  * scripts/generate_training_data.py -> labelled training dataset
  * scripts/create_sample_files.py    -> sample CSV / JSON upload files
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Labels and scenarios
# ---------------------------------------------------------------------------
NORMAL = "normal"
ATTACK_SCENARIOS = [
    "brute_force",
    "port_scan",
    "dos",
    "suspicious_frequency",
    "unusual_volume",
    "abnormal_auth",
]
ALL_LABELS = [NORMAL] + ATTACK_SCENARIOS
BENIGN_BURSTS = ["monitoring_sweep", "backup_transfer", "forgot_password"]

SCENARIO_DESCRIPTIONS = {
    "brute_force": "Many failed logins from one source against one server",
    "port_scan": "One source touching many destination ports quickly",
    "dos": "Very high request volume aimed at one service",
    "suspicious_frequency": "Internal host contacting many hosts / beaconing",
    "unusual_volume": "Large outbound data transfer to an external address",
    "abnormal_auth": "Logins to many different accounts from one external source",
}

# Kafka topic for each log source
TOPIC_BY_SOURCE = {
    "network": "network-logs",
    "server_access": "network-logs",
    "ids": "network-logs",
    "firewall": "firewall-logs",
    "authentication": "authentication-logs",
}
LOG_SOURCES = list(TOPIC_BY_SOURCE.keys())

# ---------------------------------------------------------------------------
# Simulated network
# ---------------------------------------------------------------------------
SERVERS = {
    "web": "10.0.2.10",
    "web2": "10.0.2.11",
    "db": "10.0.2.20",
    "mail": "10.0.2.25",
    "auth": "10.0.2.30",
    "file": "10.0.2.40",
    "dns": "10.0.2.53",
    "backup": "10.0.5.10",
}
MONITOR_HOST = "10.0.0.250"
WORKSTATIONS = [f"10.0.1.{i}" for i in range(10, 70)]
INTERNAL_ALL = WORKSTATIONS + list(SERVERS.values())
TEST_NETS = ["192.0.2.", "198.51.100.", "203.0.113."]
USERNAMES = [f"user{i:02d}" for i in range(1, 41)] + ["admin", "root", "svc_backup"]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]


def external_ip(rng: random.Random) -> str:
    return rng.choice(TEST_NETS) + str(rng.randint(1, 254))


def iso(ts: float) -> str:
    """Epoch seconds -> ISO-8601 UTC string with milliseconds and 'Z'."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_event(rng: random.Random, ts: float, *, log_source: str, src_ip: str, dst_ip: str,
               dst_port: int, protocol: str, packet_size: int, duration: float,
               request_count: int, failed_logins: int, event_type: str,
               network_status: str, label: str, scenario: str, username: str = "",
               src_port: int | None = None) -> dict:
    return {
        "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "timestamp": iso(ts),
        "log_source": log_source,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port if src_port is not None else rng.randint(1024, 65535),
        "dst_port": int(dst_port),
        "protocol": protocol,
        "packet_size": int(packet_size),
        "duration": round(float(duration), 3),
        "request_count": int(request_count),
        "failed_logins": int(failed_logins),
        "event_type": event_type,
        "network_status": network_status,
        "username": username,
        "is_simulated": True,
        "scenario": scenario,
        "true_label": label,
    }


# ---------------------------------------------------------------------------
# Normal traffic (one event at a time)
# ---------------------------------------------------------------------------
def normal_event(rng: random.Random, ts: float) -> dict:
    kind = rng.choices(
        ["web", "app_db", "dns", "login", "firewall", "mail", "ids_info", "ping", "file_share"],
        weights=[34, 10, 15, 12, 10, 5, 3, 4, 7],
    )[0]
    e = dict(rng=rng, ts=ts, label=NORMAL, scenario="normal_traffic")

    if kind == "web":
        return make_event(**e, log_source=rng.choice(["network", "server_access"]),
                          src_ip=external_ip(rng), dst_ip=rng.choice([SERVERS["web"], SERVERS["web2"]]),
                          dst_port=rng.choice([80, 443, 443, 443]), protocol="TCP",
                          packet_size=rng.randint(300, 1500), duration=rng.uniform(0.05, 5),
                          request_count=rng.randint(1, 30), failed_logins=0,
                          event_type="http_request", network_status=rng.choice(["established", "closed"]))
    if kind == "app_db":
        return make_event(**e, log_source="network", src_ip=rng.choice(WORKSTATIONS[:15]),
                          dst_ip=SERVERS["db"], dst_port=rng.choice([5432, 3306]), protocol="TCP",
                          packet_size=rng.randint(200, 1400), duration=rng.uniform(0.01, 2),
                          request_count=rng.randint(1, 40), failed_logins=0,
                          event_type="db_query", network_status="established")
    if kind == "dns":
        return make_event(**e, log_source="network", src_ip=rng.choice(WORKSTATIONS),
                          dst_ip=SERVERS["dns"], dst_port=53, protocol="UDP",
                          packet_size=rng.randint(60, 300), duration=rng.uniform(0.001, 0.2),
                          request_count=rng.randint(1, 4), failed_logins=0,
                          event_type="dns_query", network_status="success")
    if kind == "login":
        failed = 0 if rng.random() < 0.88 else rng.randint(1, 2)
        return make_event(**e, log_source="authentication", src_ip=rng.choice(WORKSTATIONS),
                          dst_ip=SERVERS["auth"], dst_port=rng.choice([22, 443, 389]), protocol="TCP",
                          packet_size=rng.randint(100, 600), duration=rng.uniform(0.1, 3),
                          request_count=1, failed_logins=failed, username=rng.choice(USERNAMES[:40]),
                          event_type="login", network_status="success" if failed == 0 or rng.random() < 0.7 else "failed")
    if kind == "firewall":
        blocked = rng.random() < 0.15
        return make_event(**e, log_source="firewall", src_ip=external_ip(rng),
                          dst_ip=rng.choice([SERVERS["web"], SERVERS["web2"], SERVERS["mail"]]),
                          dst_port=rng.choice([443, 80, 25]) if not blocked else rng.choice(COMMON_PORTS),
                          protocol="TCP", packet_size=rng.randint(60, 1200), duration=rng.uniform(0, 2),
                          request_count=rng.randint(1, 5), failed_logins=0,
                          event_type="firewall_allow" if not blocked else "firewall_deny",
                          network_status="allowed" if not blocked else "blocked")
    if kind == "mail":
        return make_event(**e, log_source="network", src_ip=rng.choice([external_ip(rng)] + WORKSTATIONS[:5]),
                          dst_ip=SERVERS["mail"], dst_port=rng.choice([25, 587, 993]), protocol="TCP",
                          packet_size=rng.randint(400, 1500), duration=rng.uniform(0.2, 8),
                          request_count=rng.randint(1, 10), failed_logins=0,
                          event_type="smtp_session", network_status="closed")
    if kind == "ids_info":
        return make_event(**e, log_source="ids", src_ip=rng.choice(WORKSTATIONS),
                          dst_ip=external_ip(rng), dst_port=rng.choice([80, 443]), protocol="TCP",
                          packet_size=rng.randint(200, 1200), duration=rng.uniform(0.1, 3),
                          request_count=rng.randint(1, 8), failed_logins=0,
                          event_type="ids_info", network_status="established")
    if kind == "ping":
        return make_event(**e, log_source="network", src_ip=rng.choice(WORKSTATIONS),
                          dst_ip=rng.choice(INTERNAL_ALL), dst_port=0, protocol="ICMP",
                          packet_size=rng.randint(64, 128), duration=rng.uniform(0.001, 0.05),
                          request_count=rng.randint(1, 4), failed_logins=0,
                          event_type="icmp_echo", network_status="success")
    # file_share
    return make_event(**e, log_source="network", src_ip=rng.choice(WORKSTATIONS),
                      dst_ip=SERVERS["file"], dst_port=445, protocol="TCP",
                      packet_size=rng.randint(500, 1500), duration=rng.uniform(0.5, 20),
                      request_count=rng.randint(5, 120), failed_logins=0,
                      event_type="file_access", network_status="established")


# ---------------------------------------------------------------------------
# Bursts: each returns a list of (offset_seconds, event_kwargs)
# ---------------------------------------------------------------------------
def _burst(rng, n, span):
    return sorted(rng.uniform(0, span) for _ in range(n))


def scenario_burst(rng: random.Random, scenario: str, start_ts: float) -> list[dict]:
    """Create all events of one simulated attack (or benign burst)."""
    out: list[dict] = []
    add = out.append

    if scenario == "brute_force":
        attacker = external_ip(rng) if rng.random() < 0.8 else rng.choice(WORKSTATIONS)
        target = rng.choice([SERVERS["auth"], SERVERS["web"], SERVERS["db"]])
        port = rng.choice([22, 22, 3389, 21, 443])
        slow = rng.random() < 0.25
        n, span = (rng.randint(15, 25), 20) if slow else (rng.randint(40, 90), rng.uniform(10, 20))
        users = rng.sample(["admin", "root", "administrator", "test", "oracle"], k=rng.randint(1, 2))
        for off in _burst(rng, n, span):
            add(make_event(rng, start_ts + off, log_source="authentication", src_ip=attacker, dst_ip=target,
                           dst_port=port, protocol="TCP", packet_size=rng.randint(60, 220),
                           duration=rng.uniform(0.05, 1.5), request_count=rng.randint(1, 3),
                           failed_logins=rng.randint(1, 4), event_type="login_failed",
                           network_status="failed", username=rng.choice(users),
                           label="brute_force", scenario="brute_force"))

    elif scenario == "port_scan":
        attacker = external_ip(rng) if rng.random() < 0.7 else rng.choice(WORKSTATIONS)
        target = rng.choice(INTERNAL_ALL)
        stealth = rng.random() < 0.25
        n, span = (rng.randint(20, 40), 20) if stealth else (rng.randint(60, 250), rng.uniform(8, 20))
        ports = rng.sample(range(1, 65535), k=n)
        for i, p in enumerate(rng.sample(COMMON_PORTS, k=min(len(COMMON_PORTS), n // 3))):
            ports[i] = p
        proto = "UDP" if rng.random() < 0.2 else "TCP"
        for off, port in zip(_burst(rng, n, span), ports):
            add(make_event(rng, start_ts + off, log_source=rng.choice(["firewall", "firewall", "ids"]),
                           src_ip=attacker, dst_ip=target, dst_port=port, protocol=proto,
                           packet_size=rng.randint(40, 64), duration=rng.uniform(0, 0.02),
                           request_count=1, failed_logins=0, event_type="connection_attempt",
                           network_status=rng.choice(["rejected", "blocked", "reset"]),
                           label="port_scan", scenario="port_scan"))

    elif scenario == "dos":
        attackers = [external_ip(rng) for _ in range(rng.randint(1, 3))]
        target = rng.choice([SERVERS["web"], SERVERS["web2"], SERVERS["dns"]])
        udp = target == SERVERS["dns"] or rng.random() < 0.3
        n = rng.randint(100, 250)
        for off in _burst(rng, n, rng.uniform(8, 12)):
            add(make_event(rng, start_ts + off, log_source="network", src_ip=rng.choice(attackers),
                           dst_ip=target, dst_port=53 if udp else rng.choice([80, 443]),
                           protocol="UDP" if udp else "TCP", packet_size=rng.randint(60, 600),
                           duration=rng.uniform(0, 0.5), request_count=rng.randint(150, 900),
                           failed_logins=0, event_type="udp_flood" if udp else "http_flood",
                           network_status=rng.choice(["timeout", "established", "reset"]),
                           label="dos", scenario="dos"))

    elif scenario == "suspicious_frequency":
        host = rng.choice(WORKSTATIONS)
        if rng.random() < 0.6:  # lateral movement: many internal hosts
            n = rng.randint(40, 80)
            for off in _burst(rng, n, rng.uniform(10, 15)):
                add(make_event(rng, start_ts + off, log_source=rng.choice(["network", "firewall"]),
                               src_ip=host, dst_ip=rng.choice(INTERNAL_ALL),
                               dst_port=rng.choice([445, 135, 3389, 5985]), protocol="TCP",
                               packet_size=rng.randint(60, 300), duration=rng.uniform(0.01, 0.5),
                               request_count=rng.randint(1, 3), failed_logins=0,
                               event_type="connection_attempt",
                               network_status=rng.choice(["rejected", "established"]),
                               label="suspicious_frequency", scenario="suspicious_frequency"))
        else:  # beaconing: very regular calls to one external host
            c2 = external_ip(rng)
            port = rng.choice([4444, 8443, 1337, 8080])
            n = rng.randint(30, 50)
            for i in range(n):
                add(make_event(rng, start_ts + i * 0.4 + rng.uniform(0, 0.05), log_source="network",
                               src_ip=host, dst_ip=c2, dst_port=port, protocol="TCP",
                               packet_size=rng.randint(80, 160), duration=rng.uniform(0.01, 0.1),
                               request_count=1, failed_logins=0, event_type="outbound_connection",
                               network_status="established",
                               label="suspicious_frequency", scenario="suspicious_frequency"))

    elif scenario == "unusual_volume":
        host = rng.choice(WORKSTATIONS + [SERVERS["db"], SERVERS["file"]])
        dest = external_ip(rng)
        port = rng.choice([443, 8080, 21, 53])
        for off in _burst(rng, rng.randint(6, 15), 10):
            add(make_event(rng, start_ts + off, log_source="network", src_ip=host, dst_ip=dest,
                           dst_port=port, protocol="TCP", packet_size=rng.randint(1300, 1500),
                           duration=rng.uniform(10, 120), request_count=rng.randint(1500, 8000),
                           failed_logins=0, event_type="data_transfer", network_status="established",
                           label="unusual_volume", scenario="unusual_volume"))

    elif scenario == "abnormal_auth":
        attacker = external_ip(rng)
        n = rng.randint(15, 35)
        users = rng.sample(USERNAMES, k=min(n, len(USERNAMES)))
        for off, user in zip(_burst(rng, n, rng.uniform(10, 15)), users):
            ok = rng.random() < 0.5
            add(make_event(rng, start_ts + off, log_source="authentication", src_ip=attacker,
                           dst_ip=SERVERS["auth"], dst_port=rng.choice([22, 443]), protocol="TCP",
                           packet_size=rng.randint(100, 500), duration=rng.uniform(0.1, 2),
                           request_count=1, failed_logins=0 if ok else 1, username=user,
                           event_type="login", network_status="success" if ok else "failed",
                           label="abnormal_auth", scenario="abnormal_auth"))

    # ---------------- benign look-alikes (label = normal) ----------------
    elif scenario == "monitoring_sweep":
        for off in _burst(rng, rng.randint(30, 50), 10):
            icmp = rng.random() < 0.5
            add(make_event(rng, start_ts + off, log_source="network", src_ip=MONITOR_HOST,
                           dst_ip=rng.choice(INTERNAL_ALL), dst_port=0 if icmp else 161,
                           protocol="ICMP" if icmp else "UDP", packet_size=rng.randint(64, 120),
                           duration=rng.uniform(0.001, 0.05), request_count=1, failed_logins=0,
                           event_type="health_check", network_status="success",
                           label=NORMAL, scenario="monitoring_sweep"))
    elif scenario == "backup_transfer":
        for off in _burst(rng, rng.randint(5, 10), 10):
            add(make_event(rng, start_ts + off, log_source="network", src_ip=SERVERS["file"],
                           dst_ip=SERVERS["backup"], dst_port=873, protocol="TCP",
                           packet_size=rng.randint(1300, 1500), duration=rng.uniform(10, 120),
                           request_count=rng.randint(1500, 6000), failed_logins=0,
                           event_type="data_transfer", network_status="established",
                           label=NORMAL, scenario="backup_transfer"))
    elif scenario == "forgot_password":
        user, host = rng.choice(USERNAMES[:40]), rng.choice(WORKSTATIONS)
        n = rng.randint(3, 5)
        for i, off in enumerate(_burst(rng, n, 20)):
            last = i == n - 1
            add(make_event(rng, start_ts + off, log_source="authentication", src_ip=host,
                           dst_ip=SERVERS["auth"], dst_port=443, protocol="TCP",
                           packet_size=rng.randint(100, 500), duration=rng.uniform(0.2, 2),
                           request_count=1, failed_logins=0 if last else 1, username=user,
                           event_type="login", network_status="success" if last else "failed",
                           label=NORMAL, scenario="forgot_password"))
    else:
        raise ValueError(f"Unknown scenario: {scenario}")
    return out


# ---------------------------------------------------------------------------
# Traffic simulator (keeps a queue of scheduled burst events)
# ---------------------------------------------------------------------------
class TrafficSimulator:
    """Produces a realistic mix of normal traffic and occasional bursts.

    ``tick(now, rate)`` returns the events whose timestamp falls inside
    the second [now, now + 1).
    """

    def __init__(self, seed: int | None = None, attack_probability: float = 0.02,
                 benign_burst_probability: float = 0.015):
        self.rng = random.Random(seed)
        self.attack_probability = attack_probability
        self.benign_burst_probability = benign_burst_probability
        self._pending: list[dict] = []

    def schedule(self, scenario: str, start_ts: float) -> int:
        events = scenario_burst(self.rng, scenario, start_ts)
        self._pending.extend(events)
        self._pending.sort(key=lambda ev: ev["timestamp"])
        return len(events)

    def tick(self, now: float, rate: int, forced: list[str] | None = None) -> list[dict]:
        rng = self.rng
        out = []
        n = max(0, int(rng.gauss(rate, max(1.0, rate * 0.25)))) if rate > 0 else 0
        for _ in range(n):
            out.append(normal_event(rng, now + rng.random()))
        if rng.random() < self.attack_probability:
            self.schedule(rng.choice(ATTACK_SCENARIOS), now)
        if rng.random() < self.benign_burst_probability:
            self.schedule(rng.choice(BENIGN_BURSTS), now)
        for scenario in forced or []:
            self.schedule(scenario, now)
        limit = iso(now + 1)
        while self._pending and self._pending[0]["timestamp"] < limit:
            out.append(self._pending.pop(0))
        out.sort(key=lambda ev: ev["timestamp"])
        return out

    @property
    def pending_count(self) -> int:
        return len(self._pending)

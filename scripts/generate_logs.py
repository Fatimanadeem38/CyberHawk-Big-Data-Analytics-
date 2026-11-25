"""
Continuous SIMULATED security log generator -> Apache Kafka.

Normal mode (inside Docker, started by docker-compose):
    python scripts/generate_logs.py
  The generator asks Django every few seconds whether ingestion is ON,
  what the rate is, and whether an analyst clicked a "simulate attack"
  button. Start/stop it from the web page "Log Ingestion".

Stand-alone mode (no Django needed, e.g. for testing from WSL):
    python scripts/generate_logs.py --standalone --rate 10
    python scripts/generate_logs.py --standalone --rate 5 --scenario brute_force --duration 60
  (from the WSL host use --bootstrap localhost:29092)
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections import Counter
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "kafka" / "producers"))

from event_factory import ATTACK_SCENARIOS, TrafficSimulator  # noqa: E402
from producer import SecurityLogProducer, topic_for  # noqa: E402
from unsw_replay import DatasetReplayer  # noqa: E402  (real-dataset replay)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [generator] %(levelname)s %(message)s")
log = logging.getLogger("generator")


class DjangoControl:
    """Reads the ON/OFF switch and attack requests from the Django API."""

    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/")
        self.headers = {"X-Service-Token": token}
        self.ok = False

    def fetch(self) -> dict | None:
        try:
            r = requests.get(f"{self.base}/api/ingestion/service/control/", headers=self.headers, timeout=4)
            r.raise_for_status()
            self.ok = True
            return r.json()
        except Exception as exc:  # Django may still be starting
            if self.ok:
                log.warning("Django control API unreachable: %s", exc)
            self.ok = False
            return None

    def heartbeat(self, data: dict) -> None:
        try:
            requests.post(f"{self.base}/api/ingestion/service/heartbeat/", json=data,
                          headers=self.headers, timeout=4)
        except Exception:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description="Simulated security log generator")
    ap.add_argument("--bootstrap", default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"))
    ap.add_argument("--standalone", action="store_true", help="do not use Django; run immediately")
    ap.add_argument("--rate", type=int, default=int(os.getenv("GENERATOR_DEFAULT_RATE", "8")),
                    help="normal events per second")
    ap.add_argument("--attack-probability", type=float, default=0.02,
                    help="chance per second of starting a random simulated attack")
    ap.add_argument("--scenario", choices=ATTACK_SCENARIOS, action="append",
                    help="inject this simulated attack once at start (repeatable)")
    ap.add_argument("--duration", type=int, default=0, help="stop after N seconds (0 = forever)")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    producer = SecurityLogProducer(args.bootstrap)
    sim = TrafficSimulator(seed=args.seed, attack_probability=args.attack_probability)
    control = None if args.standalone else DjangoControl(
        os.getenv("DJANGO_INTERNAL_URL", "http://django:8000"), os.getenv("SERVICE_API_TOKEN", ""))

    enabled = args.standalone or os.getenv("GENERATOR_AUTOSTART", "0") == "1"
    rate = args.rate
    forced: list[str] = list(args.scenario or [])
    by_topic: Counter = Counter()
    by_label: Counter = Counter()
    replayer: DatasetReplayer | None = None
    last_replay: dict = {}
    started = time.time()
    last_control = last_heartbeat = 0.0
    log.info("Generator ready (standalone=%s, enabled=%s, rate=%s)", args.standalone, enabled, rate)

    try:
        while True:
            now = time.time()
            if args.duration and now - started > args.duration:
                break

            # --- read the switch from Django every 3 seconds ---
            if control and now - last_control >= 3:
                last_control = now
                cfg = control.fetch()
                if cfg is not None:
                    if cfg.get("enabled") != enabled:
                        log.info("Ingestion %s by dashboard", "STARTED" if cfg.get("enabled") else "PAUSED")
                    enabled = bool(cfg.get("enabled"))
                    rate = int(cfg.get("rate", rate))
                    sim.attack_probability = float(cfg.get("attack_probability", sim.attack_probability))
                    for sc in cfg.get("scenarios", []):
                        if sc in ATTACK_SCENARIOS:
                            log.info("Dashboard requested simulated scenario: %s", sc)
                            forced.append(sc)
                    for req in cfg.get("dataset_replays", []):
                        if req.get("action") == "stop":
                            if replayer and replayer.is_alive():
                                log.info("Dashboard stopped the dataset replay")
                                replayer.stop()
                        elif replayer and replayer.is_alive():
                            log.warning("A dataset replay is already running; request ignored")
                        else:
                            log.info("Dashboard requested REAL dataset replay: %s", req)
                            replayer = DatasetReplayer(
                                lambda: SecurityLogProducer(args.bootstrap, client_id="unsw-replay"),
                                rows=req.get("rows", 20000), rate=req.get("rate", 50),
                                start_row=req.get("start_row", 0), mode=req.get("mode", "sequential"),
                                normal_fraction=req.get("normal_fraction", 0.05))
                            replayer.start()

            # Normal traffic only while enabled; requested scenarios always run.
            saved_prob = sim.attack_probability
            if not enabled:
                sim.attack_probability = 0.0
            events = sim.tick(now, rate if enabled else 0, forced)
            sim.attack_probability = saved_prob
            forced.clear()

            for ev in events:
                producer.send(ev)
                by_topic[topic_for(ev)] += 1
                by_label[ev["true_label"]] += 1

            # --- heartbeat to Django every 5 seconds ---
            if now - last_heartbeat >= 5:
                last_heartbeat = now
                hb = {
                    "running": enabled,
                    "rate": rate,
                    "attack_probability": sim.attack_probability,
                    "events_sent": producer.sent,
                    "events_failed": producer.failed,
                    "last_error": producer.last_error,
                    "pending_burst_events": sim.pending_count,
                    "by_topic": dict(by_topic),
                    "by_label": dict(by_label),
                    "replay": replayer.status() if replayer else last_replay,
                }
                if control:
                    control.heartbeat(hb)
                if enabled or events:
                    log.info("sent=%d failed=%d pending=%d topics=%s", producer.sent, producer.failed,
                             sim.pending_count, dict(by_topic))

            time.sleep(max(0.0, 1.0 - (time.time() - now)))
    except KeyboardInterrupt:
        log.info("Stopping...")
    finally:
        producer.flush()
        log.info("Done. delivered=%d failed=%d", producer.sent, producer.failed)


if __name__ == "__main__":
    main()

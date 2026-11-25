"""
Replays REAL network flows from the UNSW-NB15 full files (UNSW-NB15_1.csv ...)
into the Kafka topic "dataset-flows", at a controlled rate.

* The event time is the moment of sending ("now"). The original capture
  time is kept in the field orig_stime.
* Each replay run gets new event ids, so you can replay the same rows again.
* mode "sequential"       rows in file order (mostly normal traffic, like the real capture)
  mode "attack_enriched"  every attack row, plus only a fraction of the normal rows.
                          This makes a demo show attacks quickly. It changes the class
                          mix, so it is NOT the real traffic distribution.

Used by the generator container (button on the Log Ingestion page) and by
scripts/replay_dataset.py (command line).
"""
from __future__ import annotations

import importlib.util
import json
import logging
import random
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("unsw_nb15", ROOT / "spark" / "datasets" / "unsw_nb15.py")
unsw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(unsw)

DATASET_DIR = ROOT / "data" / "datasets" / "unsw-nb15"
TOPIC = "dataset-flows"
log = logging.getLogger("replay")


def find_replay_files() -> list[Path]:
    """Full-format files (with IP addresses) that can be replayed."""
    out = []
    for p in sorted(DATASET_DIR.glob("*.csv")):
        try:
            with p.open(encoding="utf-8", errors="replace") as f:
                if unsw.detect_format(f.readline()) == "full":
                    out.append(p)
        except OSError:
            continue
    return out


class DatasetReplayer(threading.Thread):
    def __init__(self, producer_factory, file: str | None = None, rows: int = 20000, rate: int = 50,
                 start_row: int = 0, mode: str = "sequential", normal_fraction: float = 0.05):
        super().__init__(daemon=True, name="unsw-replay")
        self.producer_factory = producer_factory
        self.file = file
        self.rows = max(1, int(rows))
        self.rate = max(1, min(2000, int(rate)))
        self.start_row = max(0, int(start_row))
        self.mode = mode if mode in ("sequential", "attack_enriched") else "sequential"
        self.normal_fraction = min(1.0, max(0.0, float(normal_fraction)))
        self.run_id = uuid.uuid4().hex[:8]
        self._stop_event = threading.Event()
        self.state = {"status": "starting", "run_id": self.run_id, "file": None, "mode": self.mode,
                      "rate": self.rate, "rows_target": self.rows, "rows_sent": 0, "rows_read": 0,
                      "last_row": None, "by_label": {}, "error": "", "started_at": None, "finished_at": None}

    def stop(self):
        self._stop_event.set()

    def status(self) -> dict:
        return dict(self.state, by_label=dict(self.state["by_label"]))

    def run(self):
        try:
            self._run()
        except Exception as exc:  # report, never crash the generator
            log.exception("replay failed")
            self.state.update(status="failed", error=str(exc)[:300])
        finally:
            self.state["finished_at"] = datetime.now(timezone.utc).isoformat()

    def _run(self):
        path = Path(self.file) if self.file else None
        if path is None or not path.exists():
            files = find_replay_files()
            if not files:
                raise FileNotFoundError(
                    "No full-format UNSW-NB15 file (with IP addresses) in data/datasets/unsw-nb15/. "
                    "Download UNSW-NB15_1.csv (see documentation/real_dataset.md). The training/testing "
                    "set files have no IPs, so they are used for training only.")
            path = files[0]
        self.state.update(status="running", file=path.name,
                          started_at=datetime.now(timezone.utc).isoformat())
        producer = self.producer_factory()
        rng = random.Random(self.run_id)
        interval = 1.0 / self.rate
        next_t = time.time()
        for row_no, rec in unsw.iter_full_file(str(path), self.start_row):
            if self._stop_event.is_set():
                self.state["status"] = "stopped"
                break
            self.state["rows_read"] += 1
            label = rec["true_label"]
            if self.mode == "attack_enriched" and label == "normal" and rng.random() > self.normal_fraction:
                continue
            event = {
                "event_id": unsw.stable_event_id(path.name, row_no, self.run_id),
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "log_source": "unsw_nb15", "is_simulated": False,
                "dataset_file": path.name, "dataset_row": row_no, **rec,
            }
            producer.send(event, topic=TOPIC)
            self.state["rows_sent"] += 1
            self.state["last_row"] = row_no
            self.state["by_label"][label] = self.state["by_label"].get(label, 0) + 1
            if self.state["rows_sent"] >= self.rows:
                break
            next_t += interval
            delay = next_t - time.time()
            if delay > 0:
                time.sleep(delay)
            elif delay < -2:          # fell far behind: do not burst to catch up
                next_t = time.time()
        producer.flush(30)
        if self.state["status"] == "running":
            self.state["status"] = "completed"
        log.info("replay %s finished: %s", self.run_id, json.dumps(self.status()))

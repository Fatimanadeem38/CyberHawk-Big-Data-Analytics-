"""
Re-train the Spark MLlib models from your PC (WSL terminal, project folder):

    python3 scripts/train_models.py                    # simulated-data models (only if missing)
    python3 scripts/train_models.py --force            # retrain simulated-data models
    python3 scripts/train_models.py --dataset unsw     # REAL dataset UNSW-NB15 (official split)

Training runs in the "spark-train" container. Afterwards the streaming job is
restarted so that it loads the new models.
"""
from __future__ import annotations
import argparse
import subprocess
import sys


def run(cmd):
    print("$", " ".join(cmd))
    return subprocess.call(cmd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="retrain the simulated-data models")
    ap.add_argument("--dataset", choices=["simulated", "unsw"], default="simulated")
    a = ap.parse_args()
    cmd = ["docker", "compose", "run", "--rm"]
    if a.force:
        cmd += ["-e", "FORCE_RETRAIN=1"]
    cmd += ["spark-train"]
    if a.dataset == "unsw":
        cmd += ["bash", "/opt/app/spark/run_training_unsw.sh"]
    code = run(cmd)
    if code != 0:
        sys.exit(code)
    run(["docker", "compose", "restart", "spark-streaming"])


if __name__ == "__main__":
    main()

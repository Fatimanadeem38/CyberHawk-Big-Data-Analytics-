"""
Creates the HDFS folder structure through WebHDFS.

    docker compose run --rm init python /app/scripts/initialize_hdfs.py
Check it in the browser: http://localhost:9870  ->  Utilities -> Browse the file system
"""
from __future__ import annotations
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hadoop" / "storage"))
import webhdfs  # noqa: E402


def main() -> None:
    for i in range(60):
        if webhdfs.namenode_ready() and webhdfs.safemode_off():
            break
        print("[hdfs] waiting for NameNode + DataNode (and safe mode off)...")
        time.sleep(4)
    else:
        raise SystemExit("HDFS not ready")
    for d in webhdfs.DIRECTORIES:
        webhdfs.mkdirs(d)
        print(f"[hdfs] ok  {d}")
    print("[hdfs] contents of /cybersecurity:",
          [s["pathSuffix"] for s in webhdfs.list_status("/cybersecurity")])


if __name__ == "__main__":
    main()

"""
Tiny WebHDFS REST client (no Hadoop install needed on the client side).
Used by the init / verify / purge scripts.
"""
from __future__ import annotations

import os

import requests

BASE_URL = os.getenv("HDFS_WEBHDFS_URL", "http://namenode:9870").rstrip("/")
USER = os.getenv("HDFS_USER", "hadoop")

# HDFS folder layout (the date folders are created by Spark: year=/month=/day=)
DIRECTORIES = [
    "/cybersecurity",
    "/cybersecurity/raw-logs",
    "/cybersecurity/processed-logs",
    "/cybersecurity/detection-results",
    "/cybersecurity/historical-alerts",
    "/cybersecurity/processing-metadata",
    "/cybersecurity/models",
    "/cybersecurity/training",
    "/cybersecurity/checkpoints",
]


def _url(path: str, op: str, **params) -> tuple[str, dict]:
    q = {"op": op, "user.name": USER, **params}
    return f"{BASE_URL}/webhdfs/v1{path}", q


def mkdirs(path: str) -> bool:
    url, q = _url(path, "MKDIRS", permission="777")
    r = requests.put(url, params=q, timeout=10)
    r.raise_for_status()
    return r.json().get("boolean", False)


def list_status(path: str) -> list[dict]:
    url, q = _url(path, "LISTSTATUS")
    r = requests.get(url, params=q, timeout=10)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return r.json()["FileStatuses"]["FileStatus"]


def content_summary(path: str) -> dict:
    url, q = _url(path, "GETCONTENTSUMMARY")
    r = requests.get(url, params=q, timeout=10)
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    return r.json()["ContentSummary"]


def delete(path: str, recursive: bool = True) -> bool:
    url, q = _url(path, "DELETE", recursive=str(recursive).lower())
    r = requests.delete(url, params=q, timeout=30)
    r.raise_for_status()
    return r.json().get("boolean", False)


def namenode_ready() -> bool:
    try:
        r = requests.get(f"{BASE_URL}/jmx", params={"qry": "Hadoop:service=NameNode,name=FSNamesystemState"}, timeout=5)
        beans = r.json().get("beans", [])
        return bool(beans) and beans[0].get("NumLiveDataNodes", 0) >= 1
    except Exception:
        return False


def safemode_off() -> bool:
    try:
        r = requests.get(f"{BASE_URL}/jmx", params={"qry": "Hadoop:service=NameNode,name=NameNodeInfo"}, timeout=5)
        beans = r.json().get("beans", [])
        return bool(beans) and not beans[0].get("Safemode")
    except Exception:
        return False

"""
UNSW-NB15: a public network-intrusion dataset (UNSW Canberra Cyber Range Lab, 2015).

Normal traffic in the dataset is real background traffic from the testbed.
The attacks were generated with the IXIA PerfectStorm tool. Both kinds of
traffic were captured as real packets (100 GB of pcap) and turned into flow
records with Argus + Bro-IDS. 10 classes: Normal + 9 attack categories.

Two CSV formats are supported (put the files in data/datasets/unsw-nb15/):

1. Official partition (used for TRAINING / EVALUATION), with a header row:
     UNSW_NB15_training-set.csv   175,341 flows
     UNSW_NB15_testing-set.csv     82,332 flows
   No IP addresses, ports or timestamps.

2. Full records (used for LIVE REPLAY through Kafka), with NO header row:
     UNSW-NB15_1.csv ... UNSW-NB15_4.csv   49 columns, incl. srcip/dstip/ports/Stime

Both are mapped to the same "canonical" column names below, so a model trained
on format 1 can score rows replayed from format 2.

This module has no top-level pyspark import, so the replay script (plain
Python) can reuse the column definitions. Spark helpers import pyspark inside.
"""
from __future__ import annotations

import csv
import hashlib
import uuid

# 49 columns of UNSW-NB15_1..4.csv, in file order (from UNSW-NB15_features.csv)
FULL_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]
# names in the full files -> names used in the training/testing set (canonical)
RENAME = {"smeansz": "smean", "dmeansz": "dmean", "res_bdy_len": "response_body_len",
          "sintpkt": "sinpkt", "dintpkt": "dinpkt"}

CATEGORICAL = ["proto", "service", "state"]

# Numeric flow features available in BOTH formats.
# Left out on purpose:
#   id, rate     - only in the partition files (id is a row number)
#   stcpb, dtcpb - random TCP sequence numbers (noise)
#   srcip/dstip/ports/stime/ltime - identify testbed hosts; using them would
#                  let the model memorise addresses instead of behaviour
NUMERIC = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "swin", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports",
]
# TTL-based features are known to be "too easy" in UNSW-NB15: in the testbed the
# attack hosts used different TTL values from the normal hosts. Training also
# runs an ablation WITHOUT them to show how much the model depends on them.
TTL_FEATURES = ["sttl", "dttl", "ct_state_ttl"]

LABELS = ["normal", "generic", "exploits", "fuzzers", "dos", "reconnaissance",
          "analysis", "backdoor", "shellcode", "worms"]

DESCRIPTIONS = {
    "generic": "Generic attack: technique that works against block ciphers regardless of key",
    "exploits": "Exploit: attacker uses a known software vulnerability",
    "fuzzers": "Fuzzing: random/malformed input sent to crash or probe a service",
    "dos": "Denial of Service: attempt to make a service unavailable",
    "reconnaissance": "Reconnaissance: scanning / information gathering",
    "analysis": "Analysis: port scans, spam and HTML-file penetrations",
    "backdoor": "Backdoor: hidden access that bypasses authentication",
    "shellcode": "Shellcode: small code payload used to exploit a vulnerability",
    "worms": "Worm: code that replicates itself to spread to other computers",
}


# ---------------------------------------------------------------------------
# plain-Python helpers (replay script)
# ---------------------------------------------------------------------------
def normalize_label(attack_cat, label=None) -> str:
    """'' / None / 'Normal' -> 'normal'; 'Backdoors' -> 'backdoor'; ' Fuzzers ' -> 'fuzzers'."""
    cat = str(attack_cat or "").strip().lower()
    if cat in ("", "normal", "-"):
        try:
            if label is not None and int(float(label)) == 1:
                return "unknown_attack"
        except (TypeError, ValueError):
            pass
        return "normal"
    return "backdoor" if cat == "backdoors" else cat


def parse_port(v) -> int:
    """Ports in the full files are decimal, hex ('0x000b') or '-'."""
    s = str(v or "").strip()
    try:
        p = int(s, 0)
    except ValueError:
        try:
            p = int(float(s))
        except ValueError:
            return 0
    return p if 0 <= p <= 65535 else 0


def to_float(v) -> float | None:
    s = str(v if v is not None else "").strip()
    if s in ("", "-", " "):
        return None
    try:
        return float(int(s, 0)) if s.lower().startswith("0x") else float(s)
    except ValueError:
        return None


def detect_format(first_line: str) -> str:
    """'partition' (header row, no IPs) or 'full' (no header, has IPs)."""
    head = first_line.strip().lower()
    if head.startswith("id,") or "attack_cat" in head:
        return "partition"
    return "full"


def full_row_to_record(row: list[str]) -> dict | None:
    """One row of UNSW-NB15_N.csv -> canonical dict (None if malformed)."""
    if len(row) < len(FULL_COLUMNS):
        return None
    raw = dict(zip(FULL_COLUMNS, row))
    rec = {RENAME.get(k, k): v for k, v in raw.items()}
    out = {
        "src_ip": rec["srcip"].strip(), "dst_ip": rec["dstip"].strip(),
        "src_port": parse_port(rec["sport"]), "dst_port": parse_port(rec["dsport"]),
        "proto": rec["proto"].strip().lower(), "service": rec["service"].strip().lower(),
        "state": rec["state"].strip().lower(),
        "true_label": normalize_label(rec["attack_cat"], rec["label"]),
        "orig_stime": to_float(rec["stime"]),
    }
    for c in NUMERIC:
        out[c] = to_float(rec.get(c))
    return out


def iter_full_file(path: str, start_row: int = 0):
    """Yield (row_number, record) from a full UNSW-NB15_N.csv file."""
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for i, row in enumerate(csv.reader(f)):
            if i < start_row:
                continue
            rec = full_row_to_record(row)
            if rec:
                yield i, rec


def stable_event_id(file_name: str, row_no: int, run_id: str) -> str:
    return str(uuid.UUID(hashlib.sha256(f"{file_name}|{row_no}|{run_id}".encode()).hexdigest()[:32]))


# ---------------------------------------------------------------------------
# Spark helpers (training + streaming)
# ---------------------------------------------------------------------------
def read_csv(spark, path: str):
    """Read either CSV format with Spark and return canonical column names (all strings)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        fmt = detect_format(f.readline())
    uri = path if "://" in path else f"file://{path}"
    if fmt == "partition":
        df = spark.read.option("header", True).csv(uri)
        df = df.toDF(*[c.strip().lower() for c in df.columns])
    else:
        df = spark.read.option("header", False).csv(uri)
        df = df.toDF(*FULL_COLUMNS[:len(df.columns)])
        for old, new in RENAME.items():
            df = df.withColumnRenamed(old, new)
    return df, fmt


def prepare(df):
    """Canonical columns -> clean model input.

    * numeric: cast to double ('-', ' ' and bad values -> 0), negatives -> 0,
      then log(1 + x) to shrink very large values (bytes, loads)
    * categorical: lower-case, '-' -> 'none'
    * true_label: normalised category name (NOT used as a feature)
    """
    from pyspark.sql import functions as F

    for c in NUMERIC:
        if c not in df.columns:
            df = df.withColumn(c, F.lit(None).cast("double"))
        v = F.col(c).cast("string")
        num = F.when(F.lower(F.trim(v)).startswith("0x"), F.conv(F.substring(F.trim(v), 3, 16), 16, 10)) \
               .otherwise(F.trim(v)).cast("double")
        df = df.withColumn(c, F.greatest(F.coalesce(num, F.lit(0.0)), F.lit(0.0)))
        df = df.withColumn(f"f_{c}", F.log1p(F.col(c)))
    for c in CATEGORICAL:
        v = F.lower(F.trim(F.coalesce(F.col(c).cast("string"), F.lit(""))))
        df = df.withColumn(c, F.when((v == "") | (v == "-"), F.lit("none")).otherwise(v))
    if "true_label" not in df.columns:
        cat = F.lower(F.trim(F.coalesce(F.col("attack_cat"), F.lit(""))))
        lab = F.coalesce(F.col("label").cast("int"), F.lit(0))
        df = df.withColumn("true_label",
                           F.when(cat == "backdoors", F.lit("backdoor"))
                            .when((cat == "") | (cat == "normal") | (cat == "-"),
                                  F.when(lab == 1, F.lit("unknown_attack")).otherwise(F.lit("normal")))
                            .otherwise(cat))
    return df


def feature_columns(drop_ttl: bool = False) -> list[str]:
    return [f"f_{c}" for c in NUMERIC if not (drop_ttl and c in TTL_FEATURES)]


def anomaly_feature_columns() -> list[str]:
    return [f"f_{c}" for c in NUMERIC]

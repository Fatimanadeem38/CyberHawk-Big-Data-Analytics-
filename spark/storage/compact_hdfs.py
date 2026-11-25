"""
Periodic file batching / compaction for HDFS.

The streaming job writes one small file per micro-batch. This job merges
all batch folders of one day into a single folder with a few large files:

  /cybersecurity/processed-logs/date=2026-11-16/batch_id=0..N   (many small)
      -> /cybersecurity/processed-logs/date=2026-11-16/batch_id=-1 (compacted)

Run it once a day (for yesterday) or whenever you like:
  docker compose exec spark-streaming /opt/spark/bin/spark-submit --master local[1] \
      /opt/app/spark/storage/compact_hdfs.py --date 2026-11-16
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone

from pyspark.sql import SparkSession

from config import settings

TARGETS = [(settings.HDFS_PROCESSED, "parquet"), (settings.HDFS_DETECTIONS, "parquet"),
           (settings.HDFS_ALERTS, "json")]


def main() -> None:
    ap = argparse.ArgumentParser()
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    ap.add_argument("--date", default=yesterday)
    ap.add_argument("--files", type=int, default=1)
    args = ap.parse_args()

    spark = SparkSession.builder.appName("HDFS-Compaction").getOrCreate()
    jvm = spark.sparkContext._jvm
    conf = spark.sparkContext._jsc.hadoopConfiguration()
    for base, fmt in TARGETS:
        day_dir = f"{base}/date={args.date}"
        path = jvm.org.apache.hadoop.fs.Path(day_dir)
        fs = path.getFileSystem(conf)
        if not fs.exists(path):
            print(f"[compact] nothing at {day_dir}")
            continue
        df = spark.read.format(fmt).load(day_dir)  # adds a batch_id column from the folder names
        rows = df.count()
        tmp = f"{base}/_compacting/date={args.date}"
        df.drop("batch_id").coalesce(args.files).write.mode("overwrite").format(fmt).save(tmp)
        fs.delete(path, True)
        fs.mkdirs(path)
        fs.rename(jvm.org.apache.hadoop.fs.Path(tmp), jvm.org.apache.hadoop.fs.Path(f"{day_dir}/batch_id=-1"))
        print(f"[compact] {day_dir}: {rows} rows -> {args.files} file(s)")
    spark.stop()


if __name__ == "__main__":
    main()

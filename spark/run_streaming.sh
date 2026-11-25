#!/usr/bin/env bash
# Starts the Spark Structured Streaming detection job.
set -e
cd /opt/app
echo "[run_streaming] starting Spark Structured Streaming (master=${SPARK_MASTER:-local[2]}) ..."
exec /opt/spark/bin/spark-submit \
  --master "${SPARK_MASTER:-local[2]}" \
  --driver-memory "${SPARK_DRIVER_MEMORY:-1200m}" \
  --conf spark.local.dir=/tmp/spark-local \
  --conf spark.ui.port=4040 \
  --conf spark.sql.streaming.metricsEnabled=true \
  /opt/app/spark/streaming/streaming_job.py

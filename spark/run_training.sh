#!/usr/bin/env bash
# Generates the simulated training data (if missing) and trains both models.
set -e
cd /opt/app
TRAIN_FILE=/opt/app/data/training/training_events.jsonl

if [ ! -s "$TRAIN_FILE" ] || [ "${FORCE_RETRAIN:-0}" = "1" ]; then
  echo "[run_training] generating simulated training data ..."
  python3 /opt/app/scripts/generate_training_data.py --target "${TRAINING_EVENTS_TARGET:-150000}"
fi

echo "[run_training] starting Spark MLlib training ..."
exec /opt/spark/bin/spark-submit \
  --master "${SPARK_MASTER:-local[2]}" \
  --driver-memory "${SPARK_TRAIN_DRIVER_MEMORY:-2g}" \
  --conf spark.local.dir=/tmp/spark-local \
  --conf spark.ui.enabled=false \
  /opt/app/spark/training/train_models.py

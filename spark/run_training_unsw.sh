#!/usr/bin/env bash
# Trains + evaluates both models on the REAL UNSW-NB15 dataset (official split).
set -e
cd /opt/app
echo "[run_training_unsw] starting Spark MLlib training on UNSW-NB15 ..."
exec /opt/spark/bin/spark-submit \
  --master "${SPARK_MASTER:-local[2]}" \
  --driver-memory "${SPARK_TRAIN_DRIVER_MEMORY:-2g}" \
  --conf spark.local.dir=/tmp/spark-local \
  --conf spark.ui.enabled=false \
  /opt/app/spark/training/train_unsw_nb15.py

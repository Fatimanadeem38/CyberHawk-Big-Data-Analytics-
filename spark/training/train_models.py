"""
Stage 5: train + evaluate + save both Spark MLlib models.

Steps
 1. Read the labelled SIMULATED training file, parse + clean + features
    (the SAME functions the streaming job uses).
 2. Store the prepared dataset in HDFS (/cybersecurity/training).
 3. Group-based train/test split (80/20): all events of one source IP in
    one time window go to the SAME side. This avoids data leakage, because
    the window features of an event are shared with its neighbours.
 4. Model A: RandomForest pipeline (encoding + scaling + classifier).
 5. Model B: KMeans anomaly pipeline trained on NORMAL training rows only.
 6. Evaluate on the test set; save models + metrics to HDFS and
    metrics to Elasticsearch (index model-metrics) for the dashboard.

Run inside the spark container:  bash /opt/app/spark/run_training.sh
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from pyspark.ml.evaluation import BinaryClassificationEvaluator, MulticlassClassificationEvaluator
from pyspark.ml.feature import StringIndexer
from pyspark.ml.functions import vector_to_array
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

from config import settings
from feature_engineering.features import ANOMALY_FEATURES, CATEGORICAL_FEATURES, NUMERIC_FEATURES, add_behavior_features
from inference.detector import models_exist
from models.pipelines import ANOMALY_QUANTILE, KMEANS_PARAMS, RF_PARAMS, build_anomaly_pipeline, build_rf_pipeline
from preprocessing.parsing import clean_events, parse_json


def binary_report(df, pred_col: str, label_col: str = "is_attack") -> dict:
    row = df.agg(
        F.sum(F.when((F.col(pred_col) == 1) & (F.col(label_col) == 1), 1).otherwise(0)).alias("tp"),
        F.sum(F.when((F.col(pred_col) == 1) & (F.col(label_col) == 0), 1).otherwise(0)).alias("fp"),
        F.sum(F.when((F.col(pred_col) == 0) & (F.col(label_col) == 0), 1).otherwise(0)).alias("tn"),
        F.sum(F.when((F.col(pred_col) == 0) & (F.col(label_col) == 1), 1).otherwise(0)).alias("fn"),
    ).first()
    tp, fp, tn, fn = (int(row[k] or 0) for k in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"accuracy": (tp + tn) / max(1, tp + tn + fp + fn), "precision": precision, "recall": recall,
            "f1": f1, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0}


def confusion(df, labels, true_col, pred_col) -> list[list[int]]:
    counts = {(r[true_col], r[pred_col]): r["count"] for r in df.groupBy(true_col, pred_col).count().collect()}
    return [[int(counts.get((t, p), 0)) for p in labels] for t in labels]


def main() -> None:
    spark = (SparkSession.builder.appName("DistributedCyberThreatDetection-Training")
             .config("spark.sql.session.timeZone", "UTC")
             .config("spark.sql.shuffle.partitions", "8")
             .getOrCreate())
    spark.sparkContext.setLogLevel("WARN")

    if models_exist(spark) and os.getenv("FORCE_RETRAIN", "0") != "1":
        print("[train] models already exist in HDFS - skipping (set FORCE_RETRAIN=1 to retrain)")
        return
    if not settings.TRAINING_FILE.exists():
        sys.exit(f"[train] training file not found: {settings.TRAINING_FILE}")

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    print(f"[train] reading {settings.TRAINING_FILE}")
    raw = spark.read.text(f"file://{settings.TRAINING_FILE}").withColumnRenamed("value", "value_str")
    events = clean_events(parse_json(raw)).dropDuplicates(["event_id"]).filter(F.col("true_label") != "")
    data = add_behavior_features(events, settings.FEATURE_WINDOW_SECONDS)
    data = data.withColumn("is_attack", F.when(F.col("true_label") == "normal", 0).otherwise(1))

    # keep a copy of the prepared training data in HDFS (distributed storage)
    data.drop("value_str").write.mode("overwrite").parquet(f"{settings.HDFS_TRAINING}/prepared_features")
    data = spark.read.parquet(f"{settings.HDFS_TRAINING}/prepared_features").cache()
    total = data.count()
    print(f"[train] prepared {total} events")

    # ---- group-based split (no leakage between train and test) ----
    group_hash = F.abs(F.hash(F.col("src_ip"), F.col("time_bucket"))) % 100
    train = data.filter(group_hash < 80).cache()
    test = data.filter(group_hash >= 80).cache()
    n_train, n_test = train.count(), test.count()
    print(f"[train] train={n_train} test={n_test}")

    # ---- labels + class weights (attacks are rarer than normal traffic) ----
    label_indexer = StringIndexer(inputCol="true_label", outputCol="label_idx",
                                  stringOrderType="frequencyDesc").fit(train)
    labels = list(label_indexer.labels)
    test = test.filter(F.col("true_label").isin(labels))  # a label never seen in training cannot be scored
    counts = {r["true_label"]: r["count"] for r in train.groupBy("true_label").count().collect()}
    weights = {l: min(10.0, max(0.5, n_train / (len(labels) * counts[l]))) for l in labels}
    weight_map = F.create_map(*[x for l, w in weights.items() for x in (F.lit(l), F.lit(float(w)))])
    train_l = label_indexer.transform(train).withColumn("class_weight", weight_map[F.col("true_label")])
    test_l = label_indexer.transform(test)

    # =================== Model A: Random Forest ===================
    print("[train] fitting RandomForest pipeline ...")
    rf_model = build_rf_pipeline().fit(train_l)
    pred = rf_model.transform(test_l)
    normal_idx = labels.index("normal")
    pred = (pred.withColumn("prob_arr", vector_to_array("probability"))
                .withColumn("attack_score", F.lit(1.0) - F.col("prob_arr")[normal_idx])
                .withColumn("pred_label", F.element_at(F.array(*[F.lit(l) for l in labels]),
                                                       F.col("prediction").cast("int") + 1))
                .withColumn("pred_attack", F.when(F.col("pred_label") == "normal", 0).otherwise(1))
                .withColumn("is_attack_d", F.col("is_attack").cast("double"))).cache()

    mc = MulticlassClassificationEvaluator(labelCol="label_idx", predictionCol="prediction")
    rf_metrics = {
        "accuracy": mc.evaluate(pred, {mc.metricName: "accuracy"}),
        "precision": mc.evaluate(pred, {mc.metricName: "weightedPrecision"}),
        "recall": mc.evaluate(pred, {mc.metricName: "weightedRecall"}),
        "f1": mc.evaluate(pred, {mc.metricName: "f1"}),
    }
    bc = BinaryClassificationEvaluator(labelCol="is_attack_d", rawPredictionCol="attack_score")
    rf_metrics["roc_auc"] = bc.evaluate(pred, {bc.metricName: "areaUnderROC"})
    rf_metrics["pr_auc"] = bc.evaluate(pred, {bc.metricName: "areaUnderPR"})
    rf_metrics["binary"] = binary_report(pred, "pred_attack")
    per_class = {}
    for i, l in enumerate(labels):
        per_class[l] = {
            "precision": mc.evaluate(pred, {mc.metricName: "precisionByLabel", mc.metricLabel: float(i)}),
            "recall": mc.evaluate(pred, {mc.metricName: "recallByLabel", mc.metricLabel: float(i)}),
            "f1": mc.evaluate(pred, {mc.metricName: "fMeasureByLabel", mc.metricLabel: float(i)}),
            "support": int(test.filter(F.col("true_label") == l).count()),
        }
    rf_metrics["per_class"] = per_class
    rf_cm = confusion(pred, labels, "true_label", "pred_label")
    importances = rf_model.stages[-1].featureImportances.toArray().tolist()
    feat_names = NUMERIC_FEATURES  # first part of the assembled vector
    top_features = sorted(zip(feat_names, importances[:len(feat_names)]), key=lambda x: -x[1])[:10]
    print(f"[train] RandomForest: {json.dumps({k: round(v, 4) for k, v in rf_metrics.items() if isinstance(v, float)})}")

    # =================== Model B: KMeans anomaly ===================
    print("[train] fitting KMeans anomaly pipeline on NORMAL training traffic ...")
    normal_train = train.filter(F.col("is_attack") == 0)
    anom_model = build_anomaly_pipeline().fit(normal_train)
    centers = [c.tolist() for c in anom_model.stages[-1].clusterCenters()]
    bc_centers = spark.sparkContext.broadcast(centers)

    @F.udf("double")
    def dist(vec, k):
        c = bc_centers.value[int(k)]
        return float(sum((float(a) - b) ** 2 for a, b in zip(vec.toArray(), c)) ** 0.5)

    train_dist = anom_model.transform(normal_train).withColumn("d", dist("anom_features", "anom_cluster"))
    threshold = float(train_dist.approxQuantile("d", [ANOMALY_QUANTILE], 0.001)[0])
    scored = (anom_model.transform(test).withColumn("d", dist("anom_features", "anom_cluster"))
              .withColumn("anomaly_score", F.col("d") / F.lit(threshold))
              .withColumn("pred_anomaly", F.when(F.col("anomaly_score") > 1.0, 1).otherwise(0))
              .withColumn("is_attack_d", F.col("is_attack").cast("double"))).cache()
    an_metrics = binary_report(scored, "pred_anomaly")
    an_metrics["roc_auc"] = BinaryClassificationEvaluator(
        labelCol="is_attack_d", rawPredictionCol="anomaly_score", metricName="areaUnderROC").evaluate(scored)
    an_metrics["detection_rate_by_category"] = {
        r["true_label"]: round(r["rate"], 4) for r in
        scored.groupBy("true_label").agg(F.avg("pred_anomaly").alias("rate")).collect()}
    an_metrics["threshold_distance"] = threshold
    an_cm = [[an_metrics["tn"], an_metrics["fp"]], [an_metrics["fn"], an_metrics["tp"]]]
    print(f"[train] Anomaly: precision={an_metrics['precision']:.4f} recall={an_metrics['recall']:.4f} "
          f"f1={an_metrics['f1']:.4f} roc_auc={an_metrics['roc_auc']:.4f} threshold={threshold:.4f}")

    # =================== save models to HDFS ===================
    label_indexer.write().overwrite().save(settings.MODEL_LABELS)
    rf_model.write().overwrite().save(settings.MODEL_RF)
    anom_model.write().overwrite().save(settings.MODEL_ANOMALY)
    spark.createDataFrame([(threshold, trained_at, ANOMALY_QUANTILE)],
                          ["threshold", "trained_at", "quantile"]) \
        .coalesce(1).write.mode("overwrite").json(settings.MODEL_ANOMALY_META)
    print(f"[train] models saved under {settings.HDFS_MODELS}")

    # =================== save metrics ===================
    common = {"trained_at": trained_at, "evaluation_type": "offline_test_set", "dataset": "simulated",
              "training_rows": n_train,
              "test_rows": n_test, "is_current": True}
    docs = [
        {**common, "model_name": "Random Forest Classifier", "model_type": "classification",
         "algorithm": "pyspark.ml.classification.RandomForestClassifier", "labels": labels,
         "metrics": rf_metrics, "confusion_matrix": {"labels": labels, "matrix": rf_cm},
         "params": {**RF_PARAMS, "class_weights": weights, "top_features": top_features},
         "feature_columns": NUMERIC_FEATURES + CATEGORICAL_FEATURES,
         "notes": "Multi-class model. Probability = share of tree votes (MLlib probability vector). "
                  "Trained and tested on SIMULATED rule-generated data, so scores are optimistic "
                  "and do not show real-world accuracy."},
        {**common, "model_name": "KMeans Distance Anomaly Detector", "model_type": "anomaly_detection",
         "algorithm": "pyspark.ml.clustering.KMeans + distance threshold (custom; MLlib has no Isolation Forest)",
         "labels": ["normal", "attack"], "metrics": an_metrics,
         "confusion_matrix": {"labels": ["normal", "attack"], "matrix": an_cm},
         "params": {**KMEANS_PARAMS, "threshold_quantile": ANOMALY_QUANTILE, "threshold_distance": threshold},
         "feature_columns": ANOMALY_FEATURES,
         "notes": "Unsupervised: trained on normal traffic only. anomaly_score = distance / threshold "
                  "(not a probability). Evaluated against the simulated labels of the test set."},
    ]
    settings.LOCAL_METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    settings.LOCAL_METRICS_FILE.write_text(json.dumps(docs, indent=2, default=str))
    spark.createDataFrame([(json.dumps(docs, default=str),)], ["value"]).coalesce(1) \
        .write.mode("overwrite").text(f"{settings.HDFS_METADATA}/model_metrics/{trained_at.replace(':', '-')}")
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(settings.ES_URL, request_timeout=30)
        es.update_by_query(index=settings.ES_MODEL_METRICS_INDEX, refresh=True, conflicts="proceed",
                           query={"bool": {"filter": [{"term": {"is_current": True}}],
                                           "must_not": [{"term": {"dataset": "unsw_nb15"}}]}},
                           script={"source": "ctx._source.is_current = false"})
        for d in docs:
            es.index(index=settings.ES_MODEL_METRICS_INDEX, document=json.loads(json.dumps(d, default=str)))
        es.indices.refresh(index=settings.ES_MODEL_METRICS_INDEX)
        print("[train] metrics written to Elasticsearch index model-metrics")
    except Exception as exc:
        print(f"[train] WARNING: could not write metrics to Elasticsearch: {exc}")
    print("[train] done")


if __name__ == "__main__":
    main()

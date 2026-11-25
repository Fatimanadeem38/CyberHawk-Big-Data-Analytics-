"""
Train and evaluate both Spark MLlib models on the REAL UNSW-NB15 dataset.

Uses the dataset authors' OFFICIAL partition, so the results can be compared
with published work and no row is in both training and testing:
    train: data/datasets/unsw-nb15/UNSW_NB15_training-set.csv   (175,341 flows)
    test:  data/datasets/unsw-nb15/UNSW_NB15_testing-set.csv    ( 82,332 flows)

Steps
 1. Read both CSVs with Spark, copy them into HDFS (/cybersecurity/datasets/unsw-nb15) as Parquet.
 2. prepare(): clean numbers, log(1+x), normalise labels.
 3. Model A  Random Forest, 10 classes (normal + 9 attack categories), class weights.
 4. Ablation Random Forest WITHOUT the TTL features (sttl, dttl, ct_state_ttl),
    to show how much the result depends on a known testbed artefact.
 5. Model B  KMeans distance anomaly detector trained on NORMAL training flows only.
 6. Evaluate everything on the official test set; save models to
    HDFS /cybersecurity/models/unsw_nb15/ and metrics to Elasticsearch
    (index model-metrics, dataset = "unsw_nb15") for the ML Models page.

Run:  python3 scripts/train_models.py --dataset unsw
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
from datasets import unsw_nb15 as unsw
from models.pipelines import (ANOMALY_QUANTILE, UNSW_KMEANS_PARAMS, UNSW_RF_PARAMS,
                              build_unsw_anomaly_pipeline, build_unsw_rf_pipeline)
from training.train_models import binary_report, confusion

TRAIN_FILE = settings.UNSW_DIR_LOCAL / "UNSW_NB15_training-set.csv"
TEST_FILE = settings.UNSW_DIR_LOCAL / "UNSW_NB15_testing-set.csv"


def evaluate_rf(model, test_l, labels):
    """Multi-class + binary metrics, per-class results and confusion matrix."""
    normal_idx = labels.index("normal")
    pred = (model.transform(test_l)
            .withColumn("prob_arr", vector_to_array("probability"))
            .withColumn("attack_score", F.lit(1.0) - F.col("prob_arr")[normal_idx])
            .withColumn("pred_label", F.element_at(F.array(*[F.lit(l) for l in labels]),
                                                   F.col("prediction").cast("int") + 1))
            .withColumn("pred_attack", F.when(F.col("pred_label") == "normal", 0).otherwise(1))
            .withColumn("is_attack_d", F.col("is_attack").cast("double"))).cache()
    mc = MulticlassClassificationEvaluator(labelCol="label_idx", predictionCol="prediction")
    m = {
        "accuracy": mc.evaluate(pred, {mc.metricName: "accuracy"}),
        "precision": mc.evaluate(pred, {mc.metricName: "weightedPrecision"}),
        "recall": mc.evaluate(pred, {mc.metricName: "weightedRecall"}),
        "f1": mc.evaluate(pred, {mc.metricName: "f1"}),
    }
    bc = BinaryClassificationEvaluator(labelCol="is_attack_d", rawPredictionCol="attack_score")
    m["roc_auc"] = bc.evaluate(pred, {bc.metricName: "areaUnderROC"})
    m["pr_auc"] = bc.evaluate(pred, {bc.metricName: "areaUnderPR"})
    m["binary"] = binary_report(pred, "pred_attack")
    support = {r["true_label"]: r["count"] for r in pred.groupBy("true_label").count().collect()}
    m["per_class"] = {l: {
        "precision": mc.evaluate(pred, {mc.metricName: "precisionByLabel", mc.metricLabel: float(i)}),
        "recall": mc.evaluate(pred, {mc.metricName: "recallByLabel", mc.metricLabel: float(i)}),
        "f1": mc.evaluate(pred, {mc.metricName: "fMeasureByLabel", mc.metricLabel: float(i)}),
        "support": int(support.get(l, 0))} for i, l in enumerate(labels)}
    cm = confusion(pred, labels, "true_label", "pred_label")
    pred.unpersist()
    return m, cm


def main() -> None:
    for f in (TRAIN_FILE, TEST_FILE):
        if not f.exists():
            sys.exit(f"[unsw] missing {f}\n"
                     "Download UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv "
                     "(see documentation/real_dataset.md) into data/datasets/unsw-nb15/")

    spark = (SparkSession.builder.appName("UNSW-NB15-Training")
             .config("spark.sql.session.timeZone", "UTC")
             .config("spark.sql.shuffle.partitions", "8")
             .getOrCreate())
    spark.sparkContext.setLogLevel("WARN")
    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    # ---- 1. read + store in HDFS ----
    for name, path in (("train", TRAIN_FILE), ("test", TEST_FILE)):
        df, fmt = unsw.read_csv(spark, str(path))
        if fmt != "partition":
            sys.exit(f"[unsw] {path.name} does not look like the official partition file (header row expected)")
        df.write.mode("overwrite").parquet(f"{settings.HDFS_DATASETS}/{name}")
        print(f"[unsw] stored {path.name} in HDFS {settings.HDFS_DATASETS}/{name}")

    def load(name):
        d = unsw.prepare(spark.read.parquet(f"{settings.HDFS_DATASETS}/{name}"))
        return d.withColumn("is_attack", F.when(F.col("true_label") == "normal", 0).otherwise(1))

    train, test = load("train").cache(), load("test").cache()
    n_train, n_test = train.count(), test.count()
    print(f"[unsw] train={n_train} test={n_test} (official partition)")
    dist = {r["true_label"]: r["count"] for r in train.groupBy("true_label").count().collect()}
    print("[unsw] training class counts:", json.dumps(dict(sorted(dist.items(), key=lambda x: -x[1]))))

    # ---- labels + class weights ----
    label_indexer = StringIndexer(inputCol="true_label", outputCol="label_idx",
                                  stringOrderType="frequencyDesc").fit(train)
    labels = list(label_indexer.labels)
    weights = {l: min(10.0, max(0.5, n_train / (len(labels) * dist[l]))) for l in labels}
    wmap = F.create_map(*[x for l, w in weights.items() for x in (F.lit(l), F.lit(float(w)))])
    train_l = label_indexer.transform(train).withColumn("class_weight", wmap[F.col("true_label")]).cache()
    test_l = label_indexer.transform(test.filter(F.col("true_label").isin(labels))).cache()

    # ---- 3. Model A ----
    feats = unsw.feature_columns()
    print(f"[unsw] fitting Random Forest on {len(feats)} numeric + {len(unsw.CATEGORICAL)} categorical features ...")
    rf_model = build_unsw_rf_pipeline(feats, unsw.CATEGORICAL).fit(train_l)
    rf_metrics, rf_cm = evaluate_rf(rf_model, test_l, labels)
    imp = rf_model.stages[-1].featureImportances.toArray().tolist()
    top_features = sorted(zip([c[2:] for c in feats], imp[:len(feats)]), key=lambda x: -x[1])[:12]
    print(f"[unsw] RF: accuracy={rf_metrics['accuracy']:.4f} f1={rf_metrics['f1']:.4f} "
          f"binary_f1={rf_metrics['binary']['f1']:.4f} roc_auc={rf_metrics['roc_auc']:.4f}")

    # ---- 4. ablation without TTL ----
    print("[unsw] ablation: Random Forest WITHOUT TTL features ...")
    abl_model = build_unsw_rf_pipeline(unsw.feature_columns(drop_ttl=True), unsw.CATEGORICAL).fit(train_l)
    abl_metrics, _ = evaluate_rf(abl_model, test_l, labels)
    rf_metrics["ablation_without_ttl"] = {
        "removed_features": unsw.TTL_FEATURES, "accuracy": abl_metrics["accuracy"], "f1": abl_metrics["f1"],
        "roc_auc": abl_metrics["roc_auc"], "binary_f1": abl_metrics["binary"]["f1"],
        "binary_recall": abl_metrics["binary"]["recall"],
        "false_positive_rate": abl_metrics["binary"]["false_positive_rate"]}
    print(f"[unsw] RF without TTL: accuracy={abl_metrics['accuracy']:.4f} f1={abl_metrics['f1']:.4f} "
          f"binary_f1={abl_metrics['binary']['f1']:.4f}")

    # ---- 5. Model B ----
    print("[unsw] fitting KMeans anomaly detector on NORMAL training flows ...")
    anom_feats = unsw.anomaly_feature_columns()
    normal_train = train.filter(F.col("is_attack") == 0)
    anom_model = build_unsw_anomaly_pipeline(anom_feats).fit(normal_train)
    centers = [c.tolist() for c in anom_model.stages[-1].clusterCenters()]
    bc_centers = spark.sparkContext.broadcast(centers)

    @F.udf("double")
    def dist_udf(vec, k):
        c = bc_centers.value[int(k)]
        return float(sum((float(a) - b) ** 2 for a, b in zip(vec.toArray(), c)) ** 0.5)

    d_train = anom_model.transform(normal_train).withColumn("d", dist_udf("anom_features", "anom_cluster"))
    threshold = float(d_train.approxQuantile("d", [ANOMALY_QUANTILE], 0.001)[0])
    scored = (anom_model.transform(test).withColumn("d", dist_udf("anom_features", "anom_cluster"))
              .withColumn("anomaly_score", F.col("d") / F.lit(threshold))
              .withColumn("pred_anomaly", F.when(F.col("anomaly_score") > 1.0, 1).otherwise(0))
              .withColumn("is_attack_d", F.col("is_attack").cast("double"))).cache()
    an = binary_report(scored, "pred_anomaly")
    an["roc_auc"] = BinaryClassificationEvaluator(labelCol="is_attack_d", rawPredictionCol="anomaly_score",
                                                  metricName="areaUnderROC").evaluate(scored)
    an["detection_rate_by_category"] = {r["true_label"]: round(r["rate"], 4) for r in
                                        scored.groupBy("true_label").agg(F.avg("pred_anomaly").alias("rate")).collect()}
    an["threshold_distance"] = threshold
    print(f"[unsw] anomaly: precision={an['precision']:.4f} recall={an['recall']:.4f} "
          f"f1={an['f1']:.4f} roc_auc={an['roc_auc']:.4f}")

    # ---- 6. save ----
    label_indexer.write().overwrite().save(settings.UNSW_MODEL_LABELS)
    rf_model.write().overwrite().save(settings.UNSW_MODEL_RF)
    anom_model.write().overwrite().save(settings.UNSW_MODEL_ANOMALY)
    spark.createDataFrame([(threshold, trained_at, ANOMALY_QUANTILE)], ["threshold", "trained_at", "quantile"]) \
        .coalesce(1).write.mode("overwrite").json(settings.UNSW_MODEL_ANOMALY_META)
    print(f"[unsw] models saved under {settings.UNSW_MODELS_DIR}")

    common = {"trained_at": trained_at, "evaluation_type": "official_test_set", "dataset": "unsw_nb15",
              "training_rows": n_train, "test_rows": n_test, "is_current": True}
    docs = [
        {**common, "model_name": "UNSW-NB15 Random Forest Classifier", "model_type": "classification",
         "algorithm": "pyspark.ml.classification.RandomForestClassifier", "labels": labels,
         "metrics": rf_metrics, "confusion_matrix": {"labels": labels, "matrix": rf_cm},
         "params": {**UNSW_RF_PARAMS, "class_weights": weights, "top_features": top_features},
         "feature_columns": [c[2:] for c in feats] + unsw.CATEGORICAL,
         "notes": "Real dataset (UNSW-NB15, UNSW Canberra 2015): real normal traffic + attacks generated with "
                  "IXIA PerfectStorm in a testbed. Trained on the official training set, evaluated on the "
                  "official testing set. 10 classes. Probability = share of tree votes. "
                  "See the ablation result for the effect of the TTL features."},
        {**common, "model_name": "UNSW-NB15 KMeans Distance Anomaly Detector", "model_type": "anomaly_detection",
         "algorithm": "pyspark.ml.clustering.KMeans + distance threshold (custom; MLlib has no Isolation Forest)",
         "labels": ["normal", "attack"], "metrics": an,
         "confusion_matrix": {"labels": ["normal", "attack"], "matrix": [[an["tn"], an["fp"]], [an["fn"], an["tp"]]]},
         "params": {**UNSW_KMEANS_PARAMS, "threshold_quantile": ANOMALY_QUANTILE, "threshold_distance": threshold},
         "feature_columns": [c[2:] for c in anom_feats],
         "notes": "Unsupervised: trained on normal training flows only, evaluated on the official testing set. "
                  "anomaly_score = distance / threshold (not a probability)."},
    ]
    settings.UNSW_LOCAL_METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    settings.UNSW_LOCAL_METRICS_FILE.write_text(json.dumps(docs, indent=2, default=str))
    spark.createDataFrame([(json.dumps(docs, default=str),)], ["value"]).coalesce(1).write.mode("overwrite") \
        .text(f"{settings.HDFS_METADATA}/model_metrics_unsw_nb15/{trained_at.replace(':', '-')}")
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(settings.ES_URL, request_timeout=30)
        es.update_by_query(index=settings.ES_MODEL_METRICS_INDEX, refresh=True, conflicts="proceed",
                           query={"bool": {"filter": [{"term": {"is_current": True}},
                                                      {"term": {"dataset": "unsw_nb15"}}]}},
                           script={"source": "ctx._source.is_current = false"})
        for d in docs:
            es.index(index=settings.ES_MODEL_METRICS_INDEX, document=json.loads(json.dumps(d, default=str)))
        es.indices.refresh(index=settings.ES_MODEL_METRICS_INDEX)
        print("[unsw] metrics written to Elasticsearch (model-metrics)")
    except Exception as exc:
        print(f"[unsw] WARNING: could not write metrics to Elasticsearch: {exc}")

    print("\n================ UNSW-NB15 RESULTS (official test set) ================")
    print(f" Random Forest (10 classes)     accuracy {rf_metrics['accuracy']:.4f}   weighted F1 {rf_metrics['f1']:.4f}")
    print(f" Random Forest attack vs normal precision {rf_metrics['binary']['precision']:.4f}  "
          f"recall {rf_metrics['binary']['recall']:.4f}  F1 {rf_metrics['binary']['f1']:.4f}  ROC-AUC {rf_metrics['roc_auc']:.4f}")
    print(f" Without TTL features            accuracy {abl_metrics['accuracy']:.4f}   binary F1 {abl_metrics['binary']['f1']:.4f}")
    print(f" KMeans anomaly (attack vs normal) precision {an['precision']:.4f}  recall {an['recall']:.4f}  "
          f"F1 {an['f1']:.4f}  ROC-AUC {an['roc_auc']:.4f}")
    print(" Per-class recall: " + ", ".join(f"{k} {v['recall']:.2f}" for k, v in rf_metrics["per_class"].items()))
    print("=======================================================================")


if __name__ == "__main__":
    os.environ.setdefault("PYSPARK_PYTHON", "python3")
    main()

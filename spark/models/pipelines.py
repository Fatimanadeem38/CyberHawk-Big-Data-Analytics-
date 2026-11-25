"""
Stage 5: Spark MLlib pipelines.

Model A - RandomForestClassifier (built into MLlib)
    multi-class: normal / brute_force / port_scan / dos /
    suspicious_frequency / unusual_volume / abnormal_auth

Model B - Distance-based anomaly detection with KMeans
    NOTE: Spark MLlib 3.5 has NO built-in Isolation Forest. We therefore
    use MLlib's KMeans trained ONLY on normal traffic. An event's anomaly
    score = (distance to its nearest cluster centre) / (99th percentile of
    that distance on normal training data). Score > 1 means "further from
    normal behaviour than 99% of normal events". This is our own method
    built on MLlib KMeans - it is not an MLlib anomaly algorithm, and the
    score is NOT a probability.

(Scaling uses withMean=False: shifting all points by the mean would not change
Euclidean distances, and it keeps sparse vectors valid.)

Both pipelines contain their own preprocessing (encoding + scaling), so the
saved PipelineModel applies exactly the same transformations at inference.
"""
from __future__ import annotations
from pyspark.ml import Pipeline
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.clustering import KMeans
from pyspark.ml.feature import OneHotEncoder, StandardScaler, StringIndexer, VectorAssembler

from feature_engineering.features import ANOMALY_FEATURES, CATEGORICAL_FEATURES, NUMERIC_FEATURES

RF_PARAMS = {"numTrees": 50, "maxDepth": 12, "maxBins": 64, "subsamplingRate": 0.8,
             "featureSubsetStrategy": "sqrt", "seed": 42}
KMEANS_PARAMS = {"k": 8, "maxIter": 40, "seed": 42}
ANOMALY_QUANTILE = 0.99


def build_rf_pipeline() -> Pipeline:
    idx_cols = [f"{c}_idx" for c in CATEGORICAL_FEATURES]
    vec_cols = [f"{c}_vec" for c in CATEGORICAL_FEATURES]
    return Pipeline(stages=[
        StringIndexer(inputCols=CATEGORICAL_FEATURES, outputCols=idx_cols, handleInvalid="keep"),
        OneHotEncoder(inputCols=idx_cols, outputCols=vec_cols, handleInvalid="keep"),
        VectorAssembler(inputCols=NUMERIC_FEATURES + vec_cols, outputCol="raw_features", handleInvalid="keep"),
        StandardScaler(inputCol="raw_features", outputCol="features", withMean=False, withStd=True),
        RandomForestClassifier(featuresCol="features", labelCol="label_idx", weightCol="class_weight",
                               predictionCol="prediction", probabilityCol="probability",
                               rawPredictionCol="rawPrediction", **RF_PARAMS),
    ])


def build_anomaly_pipeline() -> Pipeline:
    return Pipeline(stages=[
        VectorAssembler(inputCols=ANOMALY_FEATURES, outputCol="anom_raw", handleInvalid="keep"),
        StandardScaler(inputCol="anom_raw", outputCol="anom_features", withMean=False, withStd=True),
        KMeans(featuresCol="anom_features", predictionCol="anom_cluster", **KMEANS_PARAMS),
    ])


# ---------------------------------------------------------------------------
# Real dataset: UNSW-NB15 (same output column names, so ThreatDetector works)
# ---------------------------------------------------------------------------
UNSW_RF_PARAMS = {"numTrees": 80, "maxDepth": 16, "maxBins": 64, "subsamplingRate": 0.8,
                  "featureSubsetStrategy": "sqrt", "minInstancesPerNode": 2, "seed": 42}
UNSW_KMEANS_PARAMS = {"k": 12, "maxIter": 50, "seed": 42}


def build_unsw_rf_pipeline(numeric_cols: list[str], categorical_cols: list[str]) -> Pipeline:
    idx_cols = [f"{c}_idx" for c in categorical_cols]
    vec_cols = [f"{c}_vec" for c in categorical_cols]
    return Pipeline(stages=[
        StringIndexer(inputCols=categorical_cols, outputCols=idx_cols, handleInvalid="keep"),
        OneHotEncoder(inputCols=idx_cols, outputCols=vec_cols, handleInvalid="keep"),
        VectorAssembler(inputCols=numeric_cols + vec_cols, outputCol="raw_features", handleInvalid="keep"),
        StandardScaler(inputCol="raw_features", outputCol="features", withMean=False, withStd=True),
        RandomForestClassifier(featuresCol="features", labelCol="label_idx", weightCol="class_weight",
                               predictionCol="prediction", probabilityCol="probability",
                               rawPredictionCol="rawPrediction", **UNSW_RF_PARAMS),
    ])


def build_unsw_anomaly_pipeline(numeric_cols: list[str]) -> Pipeline:
    return Pipeline(stages=[
        VectorAssembler(inputCols=numeric_cols, outputCol="anom_raw", handleInvalid="keep"),
        StandardScaler(inputCol="anom_raw", outputCol="anom_features", withMean=False, withStd=True),
        KMeans(featuresCol="anom_features", predictionCol="anom_cluster", **UNSW_KMEANS_PARAMS),
    ])

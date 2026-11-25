"""
Loads the trained models from HDFS and scores events (used by streaming).

Output columns added to every event:
  predicted_class     RandomForest class (e.g. "brute_force" or "normal")
  ml_probability      RandomForest probability of the predicted class
                      (vote share of the trees, from MLlib's probability vector)
  attack_probability  1 - P(normal) from the same vector
  anomaly_score       distance / threshold from the KMeans model (NOT a probability)
  is_anomaly          anomaly_score > 1
"""
from __future__ import annotations
import math
import time

from pyspark.ml import PipelineModel
from pyspark.ml.feature import StringIndexerModel
from pyspark.ml.functions import vector_to_array
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType

from config import settings


def hdfs_path_exists(spark: SparkSession, path: str) -> bool:
    jvm = spark.sparkContext._jvm
    conf = spark.sparkContext._jsc.hadoopConfiguration()
    p = jvm.org.apache.hadoop.fs.Path(path)
    return p.getFileSystem(conf).exists(p)


SIMULATED_MODELS = {"rf": settings.MODEL_RF, "labels": settings.MODEL_LABELS,
                    "anomaly": settings.MODEL_ANOMALY, "meta": settings.MODEL_ANOMALY_META}
UNSW_MODELS = {"rf": settings.UNSW_MODEL_RF, "labels": settings.UNSW_MODEL_LABELS,
               "anomaly": settings.UNSW_MODEL_ANOMALY, "meta": settings.UNSW_MODEL_ANOMALY_META}


def models_exist(spark: SparkSession, paths: dict | None = None) -> bool:
    return all(hdfs_path_exists(spark, p) for p in (paths or SIMULATED_MODELS).values())


class ThreatDetector:
    """paths = SIMULATED_MODELS (default) or UNSW_MODELS (real dataset)."""

    def __init__(self, spark: SparkSession, wait: bool = True, paths: dict | None = None):
        self.spark = spark
        paths = paths or SIMULATED_MODELS
        while not models_exist(spark, paths):
            if not wait:
                raise RuntimeError("Trained models not found in HDFS. Run the training job first.")
            print("[detector] models not found in HDFS yet - waiting 30 s (run spark-train)")
            time.sleep(30)

        self.labels = list(StringIndexerModel.load(paths["labels"]).labels)
        self.normal_idx = self.labels.index("normal")
        self.rf_model = PipelineModel.load(paths["rf"])
        self.anomaly_model = PipelineModel.load(paths["anomaly"])
        meta = spark.read.json(paths["meta"]).first()
        self.threshold = float(meta["threshold"])
        self.model_version = str(meta["trained_at"])
        centers = [c.tolist() for c in self.anomaly_model.stages[-1].clusterCenters()]
        bc = spark.sparkContext.broadcast(centers)

        @F.udf(DoubleType())
        def distance_to_centre(vec, cluster):
            if vec is None or cluster is None:
                return None
            c = bc.value[int(cluster)]
            arr = vec.toArray()
            return float(math.sqrt(sum((float(a) - b) ** 2 for a, b in zip(arr, c))))

        self._distance = distance_to_centre
        print(f"[detector] models loaded (version {self.model_version}); labels={self.labels}; "
              f"anomaly threshold={self.threshold:.4f}")

    def score(self, features_df: DataFrame) -> DataFrame:
        labels_arr = F.array(*[F.lit(l) for l in self.labels])
        df = self.rf_model.transform(features_df)
        df = (df.withColumn("prob_arr", vector_to_array("probability"))
                .withColumn("ml_probability", F.array_max("prob_arr"))
                .withColumn("predicted_class", F.element_at(labels_arr, F.col("prediction").cast("int") + 1))
                .withColumn("attack_probability", F.lit(1.0) - F.col("prob_arr")[self.normal_idx]))
        df = self.anomaly_model.transform(df)
        df = (df.withColumn("anomaly_distance", self._distance("anom_features", "anom_cluster"))
                .withColumn("anomaly_score", F.round(F.col("anomaly_distance") / F.lit(self.threshold), 4))
                .withColumn("is_anomaly", F.col("anomaly_score") > F.lit(1.0)))
        return df.drop("raw_features", "features", "rawPrediction", "probability", "prob_arr",
                       "anom_raw", "anom_features",
                       *[c for c in df.columns if c.endswith("_idx") or c.endswith("_vec")])

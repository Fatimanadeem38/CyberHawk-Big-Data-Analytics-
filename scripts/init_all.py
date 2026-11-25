"""
Runs all one-time initialisation steps. docker-compose runs this
automatically in the "init" service before Spark and Django start.
"""
from __future__ import annotations
import initialize_hdfs
import initialize_indices
import initialize_topics

if __name__ == "__main__":
    print("=== 1/3 Kafka topics ===")
    initialize_topics.main()
    print("=== 2/3 Elasticsearch indices ===")
    initialize_indices.main()
    print("=== 3/3 HDFS directories ===")
    initialize_hdfs.main()
    print("=== initialisation complete ===")

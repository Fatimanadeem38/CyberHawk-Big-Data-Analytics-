# Spark 3.5.1 + Python 3 + the Kafka connector jars + Python libraries
FROM apache/spark:3.5.1-python3

USER root

# numpy is required by pyspark.ml; elasticsearch + requests are used by the job
RUN pip3 install --no-cache-dir "numpy<2" "elasticsearch>=8.13,<9" "requests<3"

# Kafka connector for Structured Streaming (downloaded at build time,
# so the job does not need internet access when it starts)
ADD --chown=spark:spark https://repo1.maven.org/maven2/org/apache/spark/spark-sql-kafka-0-10_2.12/3.5.1/spark-sql-kafka-0-10_2.12-3.5.1.jar /opt/spark/jars/
ADD --chown=spark:spark https://repo1.maven.org/maven2/org/apache/spark/spark-token-provider-kafka-0-10_2.12/3.5.1/spark-token-provider-kafka-0-10_2.12-3.5.1.jar /opt/spark/jars/
ADD --chown=spark:spark https://repo1.maven.org/maven2/org/apache/kafka/kafka-clients/3.4.1/kafka-clients-3.4.1.jar /opt/spark/jars/
ADD --chown=spark:spark https://repo1.maven.org/maven2/org/apache/commons/commons-pool2/2.11.1/commons-pool2-2.11.1.jar /opt/spark/jars/

ENV PYTHONPATH=/opt/app/spark \
    PYSPARK_PYTHON=python3 \
    HADOOP_USER_NAME=hadoop \
    PYTHONUNBUFFERED=1

RUN mkdir -p /tmp/spark-local && chown -R spark:spark /tmp/spark-local
WORKDIR /opt/app
USER spark

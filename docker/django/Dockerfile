# Python image used by Django, the log generator and the init scripts
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

WORKDIR /app
COPY backend/requirements.txt /tmp/requirements.txt
# timeout + retries help on slow or unstable internet
RUN pip install --upgrade pip && pip install -r /tmp/requirements.txt

# The project folder is also mounted at /app by docker-compose, so code
# changes are picked up after "docker compose restart <service>".
COPY . /app
WORKDIR /app/backend
EXPOSE 8000

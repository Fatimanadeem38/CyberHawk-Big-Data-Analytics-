# Setup guide: Windows 11 + WSL2 + Docker

This guide assumes **nothing is installed yet**. Docker runs every big service for you (Kafka, Hadoop, Spark, Elasticsearch, MongoDB), so you do **not** install Hadoop, Spark or Kafka by hand.

**What you need:** 12 GB RAM is enough (the project uses about 6–7 GB). You also need about **12 GB of free disk space**: about 6 GB for Docker images and the rest for data.

---

## Step 1: Install WSL2 (Ubuntu)

Open **PowerShell as Administrator** (Start → type *PowerShell* → right-click → *Run as administrator*):

```powershell
wsl --install -d Ubuntu-22.04
```

Restart the PC when asked. After the restart, an Ubuntu window opens. Choose a Linux **username** and **password** (remember them).

Check it (normal PowerShell):

```powershell
wsl -l -v          # Ubuntu-22.04 should show VERSION 2
```

## Step 2: Limit WSL memory (important on 12 GB RAM)

This leaves enough memory for Windows. In PowerShell:

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

Paste this, save, and close:

```ini
[wsl2]
memory=8GB
processors=4
swap=4GB
```

Then apply it:

```powershell
wsl --shutdown
```

## Step 3: Install Docker Desktop

1. Download it from https://www.docker.com/products/docker-desktop/ and install it. Keep **"Use WSL 2 instead of Hyper-V"** ticked.
2. Open Docker Desktop → **Settings → Resources → WSL integration** → turn on **Ubuntu-22.04** → *Apply & restart*.
3. *(Low disk on C:?)* Go to **Settings → Resources → Advanced → Disk image location** and choose another drive.

Check it in the **Ubuntu** terminal (Start → *Ubuntu*):

```bash
docker version
docker compose version     # must be v2.x
```

## Step 4: Put the project inside WSL

Keep the project in the Linux file system (`~/…`), not in `C:\…`. This is much faster, and Linux line endings stay correct.

```bash
sudo apt update && sudo apt install -y unzip
mkdir -p ~/projects && cd ~/projects
# change <YourWindowsName> to your Windows user folder name
cp /mnt/c/Users/<YourWindowsName>/Downloads/distributed-cyber-threat-detection.zip .
unzip distributed-cyber-threat-detection.zip
cd distributed-cyber-threat-detection
```

## Step 5: Configure passwords

```bash
cp .env.example .env
nano .env        # change the passwords; Ctrl+O to save, Ctrl+X to exit
```

At least change `MONGO_ROOT_PASSWORD`, `DJANGO_SECRET_KEY`, `DJANGO_ADMIN_PASSWORD`, `DJANGO_ANALYST_PASSWORD` and `SERVICE_API_TOKEN`.

## Step 6: Start everything

```bash
docker compose up -d --build
```

The first run downloads images and builds two images (10–20 minutes, depending on your internet). Docker then starts things **in this order** by itself:

| Order | Service | What it does | Done when |
|---|---|---|---|
| 1 | `kafka`, `namenode`, `datanode`, `elasticsearch`, `mongodb` | core services | "healthy" / "running" |
| 2 | `init` | creates Kafka topics, Elasticsearch indices, HDFS folders | **Exited (0)** |
| 3 | `spark-train` | creates the simulated training data, trains both models (3–8 min) | **Exited (0)** |
| 4 | `spark-streaming` | the real-time detection job | "running" |
| 5 | `django`, `generator` | website + log generator (generator starts *paused*) | "running" |

Watch the progress:

```bash
docker compose ps
docker compose logs -f init           # Ctrl+C stops watching (the service keeps running)
docker compose logs -f spark-train    # shows model accuracy at the end
docker compose logs -f spark-streaming
```

## Step 7: Open the dashboard

Open **http://localhost:8000** in your browser and sign in with `admin` and the password from `.env`.

1. Go to **Log Ingestion** and click **Start ingestion**.
2. Open **Live Monitoring**. New events appear every ~15 seconds (one Spark micro-batch).
3. Click **Simulate an attack → Brute-force login attempts**. An alert appears on **Security Alerts** within about 30 seconds.

## Step 8: Check that each service is running

| Service | Command (Ubuntu terminal, in the project folder) | Expected |
|---|---|---|
| All | `docker compose ps` | no service "restarting" |
| Kafka | `docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list` | 4 topics |
| Kafka messages | `docker compose exec kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic network-logs --max-messages 3` | 3 JSON events |
| HDFS | open http://localhost:9870 → *Utilities → Browse the file system* → `/cybersecurity` | folders with files |
| HDFS (CLI) | `docker compose exec namenode hdfs dfs -ls -R /cybersecurity/processed-logs \| head` | Parquet files |
| Spark | open http://localhost:4040 → *Structured Streaming* tab | 2 active queries |
| Elasticsearch | `curl -s localhost:9200/_cat/indices?v` | 5 indices with doc counts |
| MongoDB | `docker compose exec mongodb mongosh -u threat_admin -p <MONGO_ROOT_PASSWORD> --authenticationDatabase admin threatdb --eval "db.getCollectionNames()"` | Django collections |
| Django | open http://localhost:8000/system/ | all cards green |
| Everything at once | `docker compose run --rm init python /app/scripts/verify_pipeline.py` | PASS lines |

## Everyday commands

```bash
docker compose stop                 # stop (keeps all data)
docker compose start                # start again
docker compose restart django       # restart one service
docker compose logs -f django       # see errors
docker compose down                 # remove containers (data volumes are kept)
docker compose down -v              # remove EVERYTHING including data (fresh start)
python3 scripts/train_models.py --force   # retrain the models with new training data
docker compose run --rm init python /app/scripts/purge_old_data.py --days 3   # free disk space
```

To change the code: the project folder is mounted into the containers. Python changes need `docker compose restart <service>`. HTML/JS/CSS changes only need a browser refresh.

## Optional: Python on WSL (only for running scripts outside Docker)

You don't need this, because everything runs in Docker. If you want it anyway:

```bash
sudo apt install -y python3-venv python3-pip
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
python scripts/generate_logs.py --standalone --rate 5 --bootstrap localhost:29092
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `elasticsearch` keeps restarting, log says `vm.max_map_count` | In PowerShell: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`, then `docker compose up -d` |
| A container is "Killed" / exit code 137 | Not enough memory. Check `.wslconfig` (Step 2), close Chrome tabs, then `docker compose up -d` |
| `spark-train` failed | `docker compose logs spark-train` → fix → `docker compose up -d` (it runs again) |
| `spark-streaming` says "models not found" | Training has not finished yet. Wait, or run `python3 scripts/train_models.py` |
| Dashboard shows "Elasticsearch is not reachable" | `docker compose ps elasticsearch`; wait until it is healthy |
| `bash\r: No such file or directory` | The files got Windows line endings. Unzip inside WSL (Step 4), or run `sudo apt install dos2unix && find . -name "*.sh" -exec dos2unix {} \;` |
| Port 8000/9200/9870 already in use | Stop the other program, or change the left side of the port in `docker-compose.yml` (e.g. `"8080:8000"`) |
| Low disk space | `docker system prune` (removes unused images), the purge script above, and lower `KAFKA_LOG_RETENTION_HOURS` |
| Forgot the admin password | `docker compose exec django python manage.py changepassword admin` |
| No events on Live Monitoring | Is ingestion ON (Log Ingestion page)? Is `generator` running? `docker compose logs generator` |

# Testing procedure (Tests 1–9)

Run these tests after `docker compose up -d --build` has finished (`init` and `spark-train` show *Exited (0)*). Sign in as **admin**.

Useful commands (Ubuntu terminal, project folder):

```bash
docker compose run --rm init python /app/scripts/verify_pipeline.py      # PASS/WARN/FAIL for every store
docker compose logs -f spark-streaming                                     # one line per micro-batch
```

> The expected results below describe what the system is designed to do. Fill in the **Result** column with what you actually see, and take a screenshot of each test for your report.

---

### Test 1: Normal traffic
1. Log Ingestion → set the attack slider to **0%** → *Apply rate settings* → **Start ingestion**.
2. Wait 1 minute and open **Live Monitoring**.

**Expected:** rows appear every ~15 s. Almost all are `normal` with severity `none`. A few `informational`/`low` anomalies are expected, because about 1% of normal events score above the anomaly threshold by design. The Dashboard "Normal traffic events" number grows.
**Check storage:** `verify_pipeline.py` shows documents in `security-events` and files in `raw-logs` and `processed-logs`.

### Test 2: Brute-force simulation
1. Log Ingestion → **Simulate → Brute-force login attempts**.
2. Within ~30 s, open **Security Alerts**.

**Expected:** an alert with category `brute_force`, severity **high or critical**, detection methods *ML · RF* + *rule: repeated_failed_logins* (often also *Anomaly · KMeans*), and dozens of grouped events. A toast pops up on any page.
Command-line alternative: `docker compose run --rm generator python /app/scripts/generate_logs.py --standalone --rate 0 --scenario brute_force --duration 30`

### Test 3: Port scanning simulation
Click **Simulate → Port scanning**.
**Expected:** a `port_scan` alert. Its details show many destination ports, and Threat Detection shows `rule: many_destination_ports`.

### Test 4: Abnormal traffic (volume / DoS)
Click **Simulate → Denial-of-Service-like traffic**, then **Unusual traffic volume**.
**Expected:** a `dos` alert (very high request count) and an `unusual_volume` alert (MBs to an external address). Both events have high anomaly scores (> 1) on the Threat Detection page. Network Analytics shows a spike in traffic volume.

### Test 5: Real-time dashboard
1. Open the **Dashboard** in one browser tab and **Live Monitoring** in another. Do not refresh them.
2. Click any *Simulate* button.

**Expected:** the top-right badge shows **Live** (green). The KPI numbers, charts and the recent-alerts table update by themselves. New rows flash on Live Monitoring.
**Reconnection test:** `docker compose restart django`. The badge changes to *Offline · retry in …s*, then back to **Live** without a page refresh.

### Test 6: Historical storage in HDFS
```bash
docker compose exec namenode hdfs dfs -ls /cybersecurity
docker compose exec namenode hdfs dfs -ls -R /cybersecurity/raw-logs | tail -3
docker compose exec namenode hdfs dfs -ls -R /cybersecurity/processed-logs | tail -3
docker compose exec namenode hdfs dfs -cat '/cybersecurity/raw-logs/year=*/month=*/day=*/part-*' | head -2
```
**Expected:** JSON raw messages, Parquet processed files in `date=…/batch_id=…` folders, JSON alert files, and models. The System Monitoring page shows file counts per folder. You can also browse at http://localhost:9870.

### Test 7: Elasticsearch search
1. **Historical Logs:** search for a source IP from an alert. Try a subnet like `10.0.1.0/24`, a date range, a protocol and *Threat events only*. Click **Export CSV**.
2. **Security Alerts:** filter by severity *high* and search by IP.

**Expected:** the results match the filters, the total counts are shown, and the CSV downloads.
Direct check: `curl -s 'localhost:9200/security-alerts/_search?q=threat_category:brute_force&pretty' | head -40`

### Test 8: Alert management
1. Open an alert → **Assign to me & investigate**. The status becomes *Investigating*.
2. Add a note.
3. Click **Resolve** with a summary. Open another alert → **Mark false positive**.

**Expected:** the status badges change. The notes and *Workflow history* show each step with your username. In MongoDB:
```bash
docker compose exec mongodb mongosh -u threat_admin -p <MONGO_ROOT_PASSWORD> --authenticationDatabase admin threatdb --eval "db.alerts_alertstate.find({}, {alert_id:1, status:1, resolved_at:1}).toArray()"
docker compose exec mongodb mongosh -u threat_admin -p <MONGO_ROOT_PASSWORD> --authenticationDatabase admin threatdb --eval "db.accounts_auditlog.find({}, {created_at:1, username:1, action:1, target_id:1}).sort({created_at:-1}).limit(5).toArray()"
```
**Permission check:** sign in as **analyst**. Alert actions work, but Start/Stop ingestion and the Simulate buttons are disabled.

### Test 9: Service recovery
1. Keep ingestion running. Note *Total events processed* on the Dashboard.
2. `docker compose restart spark-streaming` and wait ~60 s.
3. `docker compose logs spark-streaming | tail -20`

**Expected:** the job loads the models from HDFS and **continues from its checkpoint**. The first batches after the restart contain the events that were produced while it was down. The total keeps growing with no gap, and no events are duplicated (Elasticsearch uses `event_id` as the document id).

**Extra tests:**
* `docker compose stop elasticsearch` → the dashboard shows *search offline*, and Spark retries and then restarts. `docker compose start elasticsearch` → everything recovers from the checkpoint.
* `docker compose restart kafka` → the generator log shows retries, and no messages are lost.

### Test 10: Real dataset (UNSW-NB15)
1. Download the files and train: `python3 scripts/train_models.py --dataset unsw` (see [real_dataset.md](real_dataset.md)).
2. **ML Models** page → *Real dataset: UNSW-NB15*: write down the accuracy, attack-vs-normal F1, ROC-AUC, the per-class recall, **and** the ablation result without TTL features.
3. **Log Ingestion → Replay real flows**: Sequential mode, 5,000 flows at 50/s.
4. **Live Monitoring**: flows with the green **REAL** tag and real testbed IPs appear. **Security Alerts**: alerts with UNSW categories (e.g. `exploits`, `generic`) appear.
5. **ML Models → Live detection statistics**: note the agreement with ground-truth labels for "real dataset".

**Expected:** the metrics come from the official test set (82,332 flows). Attack-vs-normal scores are higher than 10-class accuracy. Some attack categories are confused with each other. The replayed flows are stored in HDFS (`datasets/unsw-nb15/replayed-raw`, `processed-logs/…/batch_id=unsw-N`) and in Elasticsearch (`log_source = unsw_nb15`).

---

## Results table (fill in)

| Test | Date | Result (pass/fail) | Notes / screenshot file |
|---|---|---|---|
| 1 Normal traffic | | | |
| 2 Brute force | | | |
| 3 Port scan | | | |
| 4 DoS / volume | | | |
| 5 Real-time | | | |
| 6 HDFS | | | |
| 7 Search | | | |
| 8 Alert workflow | | | |
| 9 Recovery | | | |
| 10 Real dataset (UNSW-NB15) | | | |

Sample API response **shapes** are in [api.md](api.md). Your values will be different.

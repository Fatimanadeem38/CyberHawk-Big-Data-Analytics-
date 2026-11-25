# Working with a real dataset: UNSW-NB15

## 1. Why UNSW-NB15?

| Question | Answer |
|---|---|
| What is it? | Network flow records made by the UNSW Canberra Cyber Range Lab (2015). Packets were captured with tcpdump (100 GB) and turned into flows with Argus and Bro-IDS. Each flow has 49 features and a label. |
| Is it real traffic? | It is a **hybrid**. The normal traffic is real modern traffic from the testbed. The attacks are **synthetic**, generated with the IXIA PerfectStorm tool. Say this clearly in your report. |
| Classes | Normal + 9 attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms |
| Why this one? | It is widely used in research, it has an **official train/test split** (so results can be compared with papers), and it is small enough for your laptop (train + test ≈ 45 MB). The full files have real IP addresses and ports, so they can be replayed through the live pipeline. |
| Licence | Free for academic research. You **must cite** the dataset papers (listed on the download page). |

Other real datasets (CIC-IDS2017, CSE-CIC-IDS2018, NSL-KDD) could be added later. CIC-IDS2017 is several GB, which is too big for your disk right now.

## 2. Download (about 210 MB)

1. Open https://research.unsw.edu.au/projects/unsw-nb15-dataset and follow the **"download HERE"** link to the dataset folder.
2. Download these files:

| File | Folder on the download site | Size | Used for |
|---|---|---|---|
| `UNSW_NB15_training-set.csv` | *Training and Testing Sets* | ~15 MB | training (175,341 flows) |
| `UNSW_NB15_testing-set.csv` | *Training and Testing Sets* | ~30 MB | evaluation (82,332 flows) |
| `UNSW-NB15_1.csv` | *CSV Files* | ~160 MB | live replay through Kafka (≈700,000 flows with IPs and ports) |

The first two are enough for training and evaluation. The third is only needed for the live demo. You can delete it afterwards to save disk space.

3. Copy them into the project (WSL terminal, project folder; change `<YourWindowsName>`):

```bash
mkdir -p data/datasets/unsw-nb15
cp /mnt/c/Users/<YourWindowsName>/Downloads/UNSW_NB15_training-set.csv data/datasets/unsw-nb15/
cp /mnt/c/Users/<YourWindowsName>/Downloads/UNSW_NB15_testing-set.csv  data/datasets/unsw-nb15/
cp /mnt/c/Users/<YourWindowsName>/Downloads/UNSW-NB15_1.csv            data/datasets/unsw-nb15/
ls -lh data/datasets/unsw-nb15/
```

The **Log Ingestion** page now has a "Real dataset: UNSW-NB15" card that shows which files it found.

## 3. Train and evaluate (about 5–15 minutes)

```bash
docker compose up -d                          # if the platform is not running
python3 scripts/train_models.py --dataset unsw
```

This runs `spark/training/train_unsw_nb15.py` inside the Spark container, then restarts the streaming job so it loads the new models. At the end it prints a results table. You also see the results on the **ML Models** page under *Real dataset: UNSW-NB15*.

**What it does:**

| Step | Detail |
|---|---|
| Store | both CSVs are copied into HDFS `/cybersecurity/datasets/unsw-nb15/{train,test}` as Parquet |
| Features | 36 numeric flow features (bytes, packets, durations, loads, jitter, TCP timings, the dataset's connection-count features `ct_*`) with `log(1+x)` + scaling, and 3 categorical features (protocol, service, state) one-hot encoded |
| Left out on purpose | `id` (row number); `stcpb`/`dtcpb` (random TCP sequence numbers); IPs, ports and timestamps (the model would memorise testbed hosts instead of behaviour); `attack_cat`/`label` (these are the answers) |
| Model A | Random Forest, 80 trees, 10 classes, class weights for rare classes (Worms has only ~130 training rows) |
| Ablation | the same Random Forest **without** `sttl`, `dttl`, `ct_state_ttl` (see §5) |
| Model B | KMeans (k = 12) trained on **normal training flows only**. Score = distance ÷ 99th-percentile distance of normal flows |
| Evaluation | accuracy, weighted precision/recall/F1, per-class precision/recall/F1, 10×10 confusion matrix, attack-vs-normal precision/recall/F1/false-positive rate, ROC-AUC, PR-AUC; for Model B also detection rate per attack category |
| Saved | models: HDFS `/cybersecurity/models/unsw_nb15/`; metrics: Elasticsearch `model-metrics` (`dataset = unsw_nb15`), HDFS `processing-metadata/model_metrics_unsw_nb15/`, `data/processed/model_metrics_unsw_nb15.json` |

There is **no leakage between training and testing**: the dataset authors made the split, and every encoder, scaler and threshold is fitted on the training set only.

## 4. Replay real flows through the live pipeline

On **Log Ingestion → Real dataset: UNSW-NB15**, choose the number of flows, the rate and the mode, then click **Replay real flows**. Or use the command line:

```bash
docker compose run --rm generator python /app/scripts/replay_dataset.py --rows 5000 --rate 100
docker compose run --rm generator python /app/scripts/replay_dataset.py --mode attack_enriched --rows 3000
```

Path: `UNSW-NB15_1.csv` → generator → Kafka topic **`dataset-flows`** → Spark query **`dataset-detection`** (UNSW models) → HDFS + Elasticsearch → dashboard.

* The replayed flows show the green **REAL** tag (simulated events show the purple **SIM** tag). Their log source is `unsw_nb15`.
* They keep their real IP addresses and ports from the testbed (e.g. `59.166.0.x`, `149.171.126.x`, `175.45.176.x`). The event time is the time of the replay. The original capture time is kept in the Kafka message (`orig_stime`) and in the HDFS archive.
* **Sequential** mode sends the rows in file order, which is the real mix (mostly normal traffic). **Attack-enriched** mode keeps every attack flow and only 5% of normal flows, so it is good for a quick demo. Because it changes the class mix, don't use it for measuring.
* The ground-truth label travels with each flow. The ML Models page shows the **agreement between live predictions and the real labels** for replayed flows.
* HDFS: original messages go to `/cybersecurity/datasets/unsw-nb15/replayed-raw/`; processed flows go to `processed-logs/date=…/batch_id=unsw-N/`.

Important: the model was trained on the *training-set* file, while replay uses `UNSW-NB15_1.csv`. Both come from the same capture, and the training/testing sets were made from the full records. So some replayed flows may be identical to training rows. For honest numbers, use the **official test-set results** (section 3). The live replay demonstrates the pipeline with real data.

## 5. Things to explain in your report

1. **Hybrid dataset.** The normal traffic is real. The attacks are realistic but generated in a lab.
2. **The TTL artefact.** Researchers have found that in UNSW-NB15 the TTL features (`sttl`, `dttl`, `ct_state_ttl`) separate attacks from normal traffic almost by themselves, because the attacking machines in the testbed used different TTL values. A real network would not behave like that. That is why the training runs an **ablation without TTL features**. Report both numbers; the version without TTL is the more careful estimate.
3. **Multi-class is harder than attack-vs-normal.** Some categories (DoS, Exploits, Analysis, Backdoor) have very similar flow features, so they are often confused with each other in published work too. Expect the confusion matrix to show this. Attack-vs-normal (binary) scores are usually much higher than 10-class accuracy.
4. **Model B is unsupervised.** It never saw an attack during training. Its recall per category shows which attacks look "unusual" in flow features and which look like normal traffic.
5. **Your actual numbers come from your run.** Copy them from the training output or the ML Models page into the report. Do not use numbers from papers or from this guide.

## 6. Citation

Cite the papers listed on the UNSW-NB15 page, at least:
Moustafa, N. and Slay, J. (2015). "UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)." *Military Communications and Information Systems Conference (MilCIS)*, IEEE.

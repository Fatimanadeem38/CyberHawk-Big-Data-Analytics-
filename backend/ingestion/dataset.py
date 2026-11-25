"""Status of the real dataset (UNSW-NB15): files present, model trained?"""
from django.conf import settings

from core import es

DATASET_DIR = settings.REPO_ROOT / "data" / "datasets" / "unsw-nb15"
TRAIN_FILES = ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]


def _format(path) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            head = f.readline().strip().lower()
    except OSError:
        return "unreadable"
    return "partition" if head.startswith("id,") or "attack_cat" in head else "full"


def dataset_status() -> dict:
    files = []
    if DATASET_DIR.exists():
        for p in sorted(DATASET_DIR.glob("*.csv")):
            files.append({"name": p.name, "size_bytes": p.stat().st_size, "format": _format(p)})
    names = {f["name"] for f in files}
    model = None
    try:
        hits = es.hits(es.search(es.MODEL_METRICS, size=5, sort=[{"trained_at": "desc"}], query={"bool": {
            "filter": [{"term": {"dataset": "unsw_nb15"}}, {"term": {"is_current": True}}]}}))
        rf = next((h for h in hits if h.get("model_type") == "classification"), None)
        if rf:
            m = rf.get("metrics", {})
            model = {"trained_at": rf.get("trained_at"), "accuracy": m.get("accuracy"), "f1": m.get("f1"),
                     "binary_f1": (m.get("binary") or {}).get("f1"), "roc_auc": m.get("roc_auc")}
    except es.ESUnavailable:
        model = None
    return {
        "directory": "data/datasets/unsw-nb15/",
        "files": files,
        "training_files_present": all(n in names for n in TRAIN_FILES),
        "replay_files": [f["name"] for f in files if f["format"] == "full"],
        "model": model,
    }

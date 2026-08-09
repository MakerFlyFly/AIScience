"""Reproduce the offline AIScience robust-location demo."""
import csv
import json
import math
import random
import statistics
from pathlib import Path

SEED = 20260809
REPLICATES = 200
N = 50
EPS = 0.1
SCALE = 10.0
rng = random.Random(SEED)
rows = []
for replicate in range(REPLICATES):
    sample = [
        rng.gauss(0.0, SCALE if rng.random() < EPS else 1.0)
        for _ in range(N)
    ]
    rows.append(
        {
            "replicate": replicate,
            "mean": statistics.fmean(sample),
            "median": statistics.median(sample),
        }
    )
summary = {}
for estimator in ("mean", "median"):
    values = [row[estimator] for row in rows]
    summary[estimator] = {
        "bias": statistics.fmean(values),
        "rmse": math.sqrt(statistics.fmean(value * value for value in values)),
        "mae": statistics.fmean(abs(value) for value in values),
    }
root = Path(__file__).resolve().parents[1]
results = root / "results"
results.mkdir(exist_ok=True)
with (results / "trials.csv").open("w", encoding="utf-8", newline="") as stream:
    writer = csv.DictWriter(
        stream, fieldnames=["replicate", "mean", "median"], lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
(results / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)

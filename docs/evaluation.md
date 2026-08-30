# Evaluation

Run a measured safe baseline benchmark:

```bash
python -m netsentinel.evaluation.run_benchmark --scenario mixed_enterprise --events 200 --seed 42 --output-dir reports/evaluation/latest
```

The command writes counts, precision, recall, F1, macro/weighted F1, PR-AUC,
ROC-AUC where both classes exist, false positives per 10,000 events, latency
percentiles, confusion data, and hard-negative results. It records the actual
local run; no hard-coded metrics are exposed by `/api/evaluation`.

The baseline does not measure the optional ONNX wrappers and therefore does not
support claims about all six threat classes. A real-data result requires a
prepared dataset, a documented split, and a saved artifact manifest.

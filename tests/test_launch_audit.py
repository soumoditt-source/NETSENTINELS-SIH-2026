import numpy as np

from tools.launch_demo import _metric_row


def test_launch_audit_uses_explicit_binary_metrics():
    metrics = _metric_row(
        labels=np.array([0, 1, 1, 0]),
        probabilities=np.array([0.1, 0.9, 0.8, 0.2]),
        threshold=0.5,
    )

    assert metrics["rows"] == 4
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["roc_auc"] == 1.0

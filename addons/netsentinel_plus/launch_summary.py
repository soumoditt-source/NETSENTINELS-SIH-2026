"""Print the measured launch scorecard and live model status."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "reports" / "launch" / "launch_report.json"
HEALTH_URL = "http://127.0.0.1:8100/api/health"


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _live_health() -> dict[str, Any] | None:
    try:
        with urlopen(HEALTH_URL, timeout=5) as response:
            value = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, URLError):
        return None
    return value if isinstance(value, dict) else None


def _score(value: Any, digits: int = 2) -> str:
    if not isinstance(value, (int, float)):
        return "n/a"
    return f"{value:.{digits}%}"


def render_summary(report: dict[str, Any], health: dict[str, Any] | None) -> str:
    lines = [
        "",
        "=" * 72,
        " NetSentinel measured scorecard | no hard-coded accuracy claims",
        "=" * 72,
    ]
    real_data = report.get("real_data") or {}
    if real_data.get("status") == "measured_real_data":
        lines.append(f"REAL DATA: {real_data.get('dataset', 'prepared dataset')}")
        lines.append(f"  threshold={real_data.get('threshold', 'n/a')} features={real_data.get('features', 'n/a')}")
        for split in ("train", "validation", "test"):
            metrics = (real_data.get("splits") or {}).get(split) or {}
            lines.append(
                f"  {split:10} rows={metrics.get('rows', 'n/a'):>8} "
                f"accuracy={_score(metrics.get('accuracy'))} "
                f"precision={_score(metrics.get('precision'))} "
                f"recall={_score(metrics.get('recall'))} "
                f"F1={_score(metrics.get('f1'))} "
                f"ROC-AUC={_score(metrics.get('roc_auc'))}"
            )
    else:
        lines.append("REAL DATA: unavailable — run the repository dataset preparation first")

    safe = report.get("safe_pipeline") or {}
    if safe.get("status") != "not_available":
        lines.append(
            f"SAFE METADATA REPLAY: events={safe.get('events_replayed', 'n/a')} "
            f"accuracy={_score(safe.get('accuracy'))} "
            f"precision={_score(safe.get('precision'))} "
            f"recall={_score(safe.get('recall'))} "
            f"F1={_score(safe.get('f1'))} "
            f"p95_latency_ms={safe.get('latency_p95_ms', 'n/a')}"
        )

    if health:
        models = health.get("models") or {}
        loaded = models.get("models_loaded") or models.get("ml_models") or {}
        lines.append("LIVE MODEL STATUS:")
        for name, active in loaded.items():
            lines.append(f"  {name:24} {'LOADED' if active else 'UNAVAILABLE'}")
        lines.append(f"  read_only={health.get('read_only_mode')} payload_decrypted={health.get('payload_decrypted')}")
    else:
        lines.append("LIVE MODEL STATUS: backend health endpoint unavailable")

    lines.extend([
        "",
        "Interpretation: these are measured dataset/scenario results, not a universal malware accuracy rate.",
        "NetSentinel remains metadata-only, read-only, and advisory; no payloads are executed or downloaded.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    report = _read_json(REPORT_PATH)
    if report is None:
        print(f"[INFO] Launch report not found: {REPORT_PATH}")
        return 0
    print(render_summary(report, _live_health()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

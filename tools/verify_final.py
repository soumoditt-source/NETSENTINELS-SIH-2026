"""Strict, read-only verification for a judge launch."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "launch" / "launch_report.json"
EXPECTED_MODELS = ("ddos", "c2_beacon", "dga", "encrypted_traffic", "cicids2017_xgboost")
EXPECTED_RULES = ("reconnaissance", "exfiltration", "legit_service_c2", "correlation", "volumetric_flood", "dns_anomaly", "beaconing")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _get_json(url: str) -> dict[str, Any] | None:
    for attempt in range(6):
        try:
            with urlopen(url, timeout=8) as response:
                value = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, URLError):
            if attempt < 5:
                time.sleep(2)
    return None


def _http_ok(url: str) -> bool:
    for attempt in range(6):
        try:
            with urlopen(url, timeout=8) as response:
                return response.status == 200
        except (OSError, URLError):
            if attempt < 5:
                time.sleep(2)
    return False


def verify(backend_url: str, frontend_url: str, require_frontend: bool = True) -> tuple[bool, list[str]]:
    checks: list[tuple[str, bool, str]] = []
    report = _read_json(REPORT_PATH)
    checks.append(("launch report", report is not None, str(REPORT_PATH.relative_to(ROOT))))

    if report:
        real_data = report.get("real_data") or {}
        splits = real_data.get("splits") or {}
        real_ok = real_data.get("status") == "measured_real_data" and all(split in splits for split in ("train", "validation", "test"))
        checks.append(("real-data scorecard", real_ok, "train + validation + test"))
        safe = report.get("safe_pipeline") or {}
        checks.append(("safe replay scorecard", safe.get("status") != "not_available", "metadata-only fixture"))
        safety = report.get("safety") or {}
        checks.append(("report read-only", safety.get("read_only") is True, "read_only=true"))
        checks.append(("report no decryption", safety.get("payload_decrypted") is False, "payload_decrypted=false"))

    health = _get_json(f"{backend_url.rstrip('/')}/api/health")
    checks.append(("backend health", health is not None, backend_url))
    if health:
        models = (health.get("models") or {}).get("models_loaded") or {}
        rules = (health.get("models") or {}).get("rule_detectors") or {}
        checks.extend((f"model:{name}", models.get(name) is True, "loaded") for name in EXPECTED_MODELS)
        checks.extend((f"rule:{name}", rules.get(name) is True, "loaded") for name in EXPECTED_RULES)
        checks.append(("live read-only", health.get("read_only_mode") is True, "read_only_mode=true"))
        checks.append(("live no decryption", health.get("payload_decrypted") is False, "payload_decrypted=false"))

    if require_frontend:
        frontend_ok = _http_ok(frontend_url)
        checks.append(("dashboard HTTP", frontend_ok, frontend_url))

    failures = [f"{name}: {detail}" for name, ok, detail in checks if not ok]
    print("\nNetSentinel final verification")
    print("-" * 72)
    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL':4} | {name:24} | {detail}")
    print("-" * 72)
    print(f"Result: {'PASS' if not failures else 'FAIL'} ({len(checks) - len(failures)}/{len(checks)} checks)")
    return not failures, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8100")
    parser.add_argument("--frontend-url", default="http://127.0.0.1:5174")
    parser.add_argument("--skip-frontend", action="store_true")
    args = parser.parse_args()
    ok, _ = verify(args.backend_url, args.frontend_url, require_frontend=not args.skip_frontend)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

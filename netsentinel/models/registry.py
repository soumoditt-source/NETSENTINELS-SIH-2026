"""Model Registry — Loads optional ML artifacts and deterministic detectors.

Usage:
    registry = ModelRegistry()
    registry.load_all()

    result = registry.ddos.predict(flow_features)
    recon_result = registry.recon.predict(event, host_state)
"""
import time
from netsentinel.detectors.reconnaissance import ReconnaissanceRuleDetector
from netsentinel.detectors.exfiltration import ExfiltrationBaselineDetector
from netsentinel.detectors.legitimate_service_c2 import LegitimateServiceC2Detector
from netsentinel.detectors.correlation import CorrelationEngine
from netsentinel.detectors.volumetric import VolumetricFloodRuleDetector
from netsentinel.detectors.dns_anomaly import DNSAnomalyRuleDetector
from netsentinel.detectors.beaconing import BeaconingRuleDetector


class ModelRegistry:
    """Loads and holds all ONNX models and deterministic detector instances."""

    def __init__(self):
        # ML models (ONNX)
        self.ddos = None
        self.c2 = None
        self.dga = None
        self.ett = None
        self.cic_xgb = None
        self.volumetric = None
        self.dga_rule = None
        self.beacon_rule = None
        # Deterministic / rule-based detectors
        self.recon = None
        self.exfil = None
        self.c2_legit = None
        self.correlation = None
        self._load_times = {}

    def load_all(self):
        """Load all models and detectors. Call once on server startup."""
        print("\n[*] Loading AI models and detectors...")
        total_start = time.time()

        # ── ML Models ──────────────────────────────────────────────────────
        ml_models = []
        try:
            from netsentinel.models.ddos import DDoSDetector
            from netsentinel.models.c2_beacon import C2BeaconDetector
            from netsentinel.models.dga import DGADetector
            from netsentinel.models.encrypted import EncryptedTrafficDetector

            ml_models = [
                ("DDoS (XGBoost)", "ddos", DDoSDetector),
                ("C2 Beacon (BiLSTM)", "c2", C2BeaconDetector),
                ("DGA (CNN-BiLSTM)", "dga", DGADetector),
                ("Encrypted Traffic (Tfmr)", "ett", EncryptedTrafficDetector),
            ]
        except ImportError as exc:
            print(f"  [INFO] Optional ML dependencies unavailable: {exc}")
        for name, attr, cls in ml_models:
            start = time.time()
            try:
                setattr(self, attr, cls())
                self._load_times[name] = round(time.time() - start, 3)
            except Exception as e:
                print(f"  [FAIL] {name}: {e}")
                self._load_times[name] = -1

        start = time.time()
        try:
            from netsentinel.models.cicids_xgboost import CICIDSXGBoostDetector
            self.cic_xgb = CICIDSXGBoostDetector()
            self._load_times["CIC-IDS2017 XGBoost"] = round(time.time() - start, 3)
            print("  [OK] CIC-IDS2017 XGBoost loaded (trusted local artifact)")
        except FileNotFoundError:
            self._load_times["CIC-IDS2017 XGBoost"] = -1
            print("  [INFO] CIC-IDS2017 XGBoost artifact not present; run opt-in training")
        except Exception as exc:
            self._load_times["CIC-IDS2017 XGBoost"] = -1
            print(f"  [FAIL] CIC-IDS2017 XGBoost: {exc}")

        # ── Deterministic Detectors ────────────────────────────────────────
        rule_detectors = [
            ("Volumetric Flood Baseline", "volumetric", VolumetricFloodRuleDetector),
            ("DNS Anomaly Baseline",   "dga_rule",     DNSAnomalyRuleDetector),
            ("Beaconing Baseline",     "beacon_rule",  BeaconingRuleDetector),
            ("Recon Baseline",       "recon",       ReconnaissanceRuleDetector),
            ("Exfil Baseline",       "exfil",       ExfiltrationBaselineDetector),
            ("Legit-Service C2",     "c2_legit",    LegitimateServiceC2Detector),
            ("Correlation Engine",   "correlation", CorrelationEngine),
        ]
        for name, attr, cls in rule_detectors:
            start = time.time()
            try:
                setattr(self, attr, cls())
                self._load_times[name] = round(time.time() - start, 3)
            except Exception as e:
                print(f"  [FAIL] {name}: {e}")
                self._load_times[name] = -1

        total_elapsed = time.time() - total_start
        loaded = sum(1 for v in self._load_times.values() if v >= 0)
        total = len(self._load_times)
        print(f"\n[OK] {loaded}/{total} components loaded in {total_elapsed:.2f}s")

        return self

    def get_status(self) -> dict:
        """Return model/detector status for the /health endpoint."""
        ml_models = {
            "ddos": self.ddos is not None,
            "c2_beacon": self.c2 is not None,
            "dga": self.dga is not None,
            "encrypted_traffic": self.ett is not None,
            "cicids2017_xgboost": self.cic_xgb is not None,
        }
        return {
            "ml_models": ml_models,
            "models_loaded": ml_models,
            "rule_detectors": {
                "reconnaissance":    self.recon       is not None,
                "exfiltration":      self.exfil       is not None,
                "legit_service_c2":  self.c2_legit    is not None,
                "correlation":       self.correlation is not None,
                "volumetric_flood":  self.volumetric is not None,
                "dns_anomaly":       self.dga_rule is not None,
                "beaconing":         self.beacon_rule is not None,
            },
            "trained_artifacts": {
                "cicids2017_xgboost": self.cic_xgb is not None,
            },
            "load_times_ms": {
                k: int(v * 1000) if v >= 0 else "FAILED"
                for k, v in self._load_times.items()
            },
        }

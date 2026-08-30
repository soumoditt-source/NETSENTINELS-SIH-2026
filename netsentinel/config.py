"""NetSentinel configuration with safe, local-only runtime defaults."""

import os
from pathlib import Path

# ============================================================
# SIH 26145 Constraints
# ============================================================
READ_ONLY_MODE = True
NO_DECRYPTION_MODE = True

# ============================================================
# Hugging Face Model Repository
# ============================================================
HF_REPO_ID = "Unded-17/netsentinel-models"
HF_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "netsentinel", "models")
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# ============================================================
# Model Paths (with auto-download from HuggingFace)
# ============================================================
def get_model_path(relative_path: str, allow_download: bool = False) -> str:
    """
    Resolve a model file without performing network I/O by default.
    
    Args:
        relative_path: Path relative to models folder (e.g., "Ddos_detection/ddos_binary_xgboost.onnx")
    
    Returns:
        Absolute path to the model file
    """
    candidates = (
        PROJECT_ROOT / "models" / relative_path,
        Path(os.path.expanduser("~")) / "OneDrive" / "Desktop" / "models" / relative_path,
        Path(HF_CACHE_DIR) / relative_path,
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    if allow_download:
        from huggingface_hub import hf_hub_download

        cache_path = Path(HF_CACHE_DIR) / relative_path
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        return hf_hub_download(
            repo_id=HF_REPO_ID,
            filename=relative_path,
            cache_dir=HF_CACHE_DIR,
            local_dir=HF_CACHE_DIR,
            local_dir_use_symlinks=False,
        )

    return str(candidates[0])


# Model paths using auto-download
DDOS_MODEL_PATH = get_model_path("Ddos_detection/ddos_binary_xgboost.onnx")
DDOS_FEATURES_PATH = get_model_path("Ddos_detection/feature_names.json")
DDOS_LABELS_PATH = get_model_path("Ddos_detection/label_mapping.json")

C2_MODEL_PATH = get_model_path("c2_beacon_detector/c2_beacon_bilstm.onnx")
C2_SEQ_MEAN_PATH = get_model_path("c2_beacon_detector/scaler_seq_mean.npy")
C2_SEQ_SCALE_PATH = get_model_path("c2_beacon_detector/scaler_seq_scale.npy")
C2_FFT_MEAN_PATH = get_model_path("c2_beacon_detector/scaler_fft_mean.npy")
C2_FFT_SCALE_PATH = get_model_path("c2_beacon_detector/scaler_fft_scale.npy")

DGA_MODEL_PATH = get_model_path("dga_dna_tunneling_detection/dga_cnn_bilstm_v2.onnx")

ETT_MODEL_PATH = get_model_path("encrypted_traffic_transformer/encrypted_traffic_transformer.onnx")
ETT_SCALER_PATH = get_model_path("encrypted_traffic_transformer/ett_scaler.json")
ETT_CLASSES_PATH = get_model_path("encrypted_traffic_transformer/ett_classes.json")

# ============================================================
# Detection Thresholds
# ============================================================
# If a model's confidence exceeds this threshold, an alert is generated.
THRESHOLDS = {
    "ddos": 0.95,
    "c2_beacon": 0.80,
    "dga": 0.80,
    "encrypted_malware": 0.70,
    "port_scan": 0.80,
    "data_exfiltration": 0.85,
}

# ============================================================
# Severity Mapping
# ============================================================
# Maps threat class → default severity (can be overridden by confidence)
SEVERITY_MAP = {
    "DDoS": "CRITICAL",
    "C2 Beacon": "HIGH",
    "DGA": "HIGH",
    "DNS Tunnel": "HIGH",
    "VPN Traffic": "MEDIUM",
    "Encrypted Malware": "CRITICAL",
    "Port Scan": "MEDIUM",
    "Data Exfiltration": "CRITICAL",
    "CIC behavioral anomaly": "MEDIUM",
}

# ============================================================
# MITRE ATT&CK Mapping
# ============================================================
MITRE_MAP = {
    "DDoS": {"tactic": "Impact", "technique": "T1498", "name": "Network Denial of Service"},
    "C2 Beacon": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
    "DGA": {"tactic": "Command and Control", "technique": "T1568", "name": "Dynamic Resolution"},
    "DNS Tunnel": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "VPN Traffic": {"tactic": "Defense Evasion", "technique": "T1572", "name": "Protocol Tunneling"},
    "Encrypted Malware": {"tactic": "Command and Control", "technique": "T1573", "name": "Encrypted Channel"},
    "Port Scan": {"tactic": "Reconnaissance", "technique": "T1046", "name": "Network Service Discovery"},
    "Data Exfiltration": {"tactic": "Exfiltration", "technique": "T1041", "name": "Exfiltration Over C2 Channel"},
}

# ============================================================
# Server Config
# ============================================================
HOST = "0.0.0.0"
PORT = int(os.getenv("NETSENTINEL_PORT", "8100"))
MAX_ALERTS_STORED = 1000  # Keep last N alerts in memory

# ============================================================
# Simulator Config
# ============================================================
SIMULATOR_NORMAL_RATE = 10    # Normal flows per second
SIMULATOR_ATTACK_RATE = 100   # Attack flows per second during burst

# Fake geo-IP locations for demo (attacker origins)
FAKE_GEO = {
    "attacker_1": {"ip": "185.220.101.34", "country": "RU", "lat": 55.75, "lon": 37.62, "city": "Moscow"},
    "attacker_2": {"ip": "116.31.116.42", "country": "CN", "lat": 23.13, "lon": 113.26, "city": "Guangzhou"},
    "attacker_3": {"ip": "45.33.32.156", "country": "US", "lat": 37.39, "lon": -122.08, "city": "Mountain View"},
    "attacker_4": {"ip": "91.189.89.88", "country": "GB", "lat": 51.51, "lon": -0.13, "city": "London"},
    "attacker_5": {"ip": "103.224.182.250", "country": "IN", "lat": 19.08, "lon": 72.88, "city": "Mumbai"},
}

# Target server (your "protected" server)
TARGET = {"ip": "10.0.0.1", "country": "IN", "lat": 28.61, "lon": 77.21, "city": "New Delhi"}

# ============================================================
# Extraction Layer Config
# ============================================================
FLOW_IDLE_TIMEOUT = 120       # Seconds of inactivity before a flow is flushed
FLOW_ACTIVE_TIMEOUT = 300     # Max seconds a flow can stay open
SESSION_MIN_FLOWS = 100       # Flows needed per (src, dst) pair for C2 detection
CAPTURE_INTERFACE = "Ethernet"  # Default Windows interface name (change for Linux)
PCAP_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "uploads")
os.makedirs(PCAP_UPLOAD_DIR, exist_ok=True)

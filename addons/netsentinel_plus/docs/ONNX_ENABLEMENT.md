# ONNX enablement and verification

## Why models were missing

The repository already contained the four ONNX artifacts and wrappers. The
runtime environment was missing the `onnxruntime` Python package, so startup
correctly skipped those optional imports instead of crashing the service.

## Install the declared dependencies

From the repository root in PowerShell:

```powershell
Set-Location "D:\PORT SCANNING CYS IP FLOW\testing-main"
python -m pip install -r requirements.txt
```

The current verified environment uses Python `3.14` and `onnxruntime 1.29.0`.
The repository requirement remains the source of truth for a fresh setup.

## Verify every model

```powershell
python -c "from netsentinel.models.registry import ModelRegistry; r=ModelRegistry().load_all(); print(r.get_status())"
```

Expected result:

```text
[OK] DDoS Detector loaded
[OK] C2 Beacon Detector loaded
[OK] DGA Detector loaded
[OK] Encrypted Traffic Detector loaded
[OK] CIC-IDS2017 XGBoost loaded
[OK] 12/12 components loaded
```

Then restart the application and inspect the live health response:

```powershell
curl.exe http://127.0.0.1:8100/api/health
```

The response must show `true` for `ddos`, `c2_beacon`, `dga`,
`encrypted_traffic`, and `cicids2017_xgboost`.

## Safe inference smoke test

The wrapper smoke test uses only empty or benign metadata vectors. It confirms
that input schemas, external-data files, and ONNX sessions are compatible; it
does not claim that a benign vector is an attack or that a model is universally
accurate.

```powershell
python -c "from netsentinel.models.ddos import DDoSDetector; from netsentinel.models.c2_beacon import C2BeaconDetector; from netsentinel.models.dga import DGADetector; from netsentinel.models.encrypted import EncryptedTrafficDetector; print(DDoSDetector().predict({})['threat']); print(C2BeaconDetector().predict([{'iat':1.0,'packet_size':100,'bytes':1000,'direction':0}]*100)['threat']); print(DGADetector().predict('www.example.com')['threat']); print(EncryptedTrafficDetector().predict({})['threat'])"
```

## Operational truth

ONNX availability is now verified in the current environment. Model loading is
not the same as model validity: real-world performance still requires
independent, labeled, temporally separated traffic and per-threat evaluation.


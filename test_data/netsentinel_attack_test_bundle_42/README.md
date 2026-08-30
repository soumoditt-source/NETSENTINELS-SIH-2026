# NetSentinel safe metadata test bundle

This bundle contains synthetic flow/DNS metadata only. It is not a malware sample, exploit, packet capture, or executable file. It is designed to exercise NetSentinel's read-only detector and temporal forensics paths offline.

## Test in the dashboard

1. Start NetSentinel on ports 8100 and 5174.
2. Open `http://localhost:5174` and click **Launch analysis**.
3. Switch to **Explain**, choose `attack_signatures_42.jsonl`, `.csv`, or `.parquet`, and inspect the alert evidence.

## Test with the API

```bash
curl -X POST http://localhost:8100/api/forensics/upload -F 'file=@attack_signatures_42.jsonl'
curl http://localhost:8100/api/forensics/temporal
```

All records use documentation-only addresses and carry explicit ground truth in `_ground_truth`.

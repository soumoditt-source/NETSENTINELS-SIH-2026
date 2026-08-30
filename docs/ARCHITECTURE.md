# Architecture

```text
PCAP / Zeek / CSV / JSONL / Parquet
              |
      read-only adapters
              |
      validated normalized event
              |
       bounded streaming state
              |
  flow + DNS + TLS metadata features
              |
 rules / optional local ML wrappers
              |
       evidence correlation
              |
   versioned alert + explanation
              |
       REST / WebSocket / UI
```

Runtime has no dataset or model download path. PCAP parsing is offline and
payload bytes are not retained as detection features. The UI may use mock
events only when a live WebSocket is unavailable in a preview sandbox; those
events are visibly synthetic in the frontend state.

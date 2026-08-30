import json
from typing import Iterator
from netsentinel.ingest.normalized_event import NormalizedEvent

class ZeekAdapter:
    """
    Reads Zeek JSON logs incrementally.
    Avoids payload decryption and enforces read-only mode.
    """
    def __init__(self, config=None):
        self.config = config
    
    def parse_conn_log(self, filepath: str) -> Iterator[NormalizedEvent]:
        """Parse a Zeek conn.log JSON file incrementally."""
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    record = json.loads(line)
                    yield self._conn_to_normalized(record)
                except Exception as e:
                    # Skip malformed lines
                    pass
                    
    def _conn_to_normalized(self, record: dict) -> NormalizedEvent:
        return NormalizedEvent(
            source_type="zeek",
            flow_id=record.get("uid", ""),
            src_ip=record.get("id.orig_h", ""),
            dst_ip=record.get("id.resp_h", ""),
            src_port=record.get("id.orig_p", 0),
            dst_port=record.get("id.resp_p", 0),
            protocol=record.get("proto", "unknown"),
            direction="outbound" if record.get("local_orig") else "inbound",
            packets=record.get("orig_pkts", 0) + record.get("resp_pkts", 0),
            bytes=record.get("orig_bytes", 0) + record.get("resp_bytes", 0),
            duration=record.get("duration", 0.0),
            first_seen=record.get("ts", 0.0),
            last_seen=record.get("ts", 0.0) + record.get("duration", 0.0),
            tcp_flags=record.get("conn_state", ""),
            raw_reference=record
        )

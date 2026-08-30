from pathlib import Path
from typing import Iterator
from netsentinel.ingest.normalized_event import NormalizedEvent

class PcapAdapter:
    """
    Reads PCAP files and converts to NormalizedEvent.
    Enforces read-only constraint.
    """
    def __init__(self, config=None):
        self.config = config
        
    def parse_pcap(self, filepath: str) -> Iterator[NormalizedEvent]:
        """Stream completed metadata flows from a local PCAP file."""

        path = Path(filepath).resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        from netsentinel.extractor.pcap_reader import PacketProcessor

        processor = PacketProcessor()
        for event in processor.process_pcap(str(path)):
            if event.get("type") != "flow":
                continue
            features = event.get("features", {})
            fwd_packets = int(features.get("Total Fwd Packets", 0) or 0)
            rev_packets = int(features.get("Total Backward Packets", 0) or 0)
            fwd_bytes = int(features.get("Fwd Packets Length Total", 0) or 0)
            rev_bytes = int(features.get("Bwd Packets Length Total", 0) or 0)
            first_seen = float(event.get("first_seen", event.get("observed_at", 0.0)))
            last_seen = float(event.get("last_seen", first_seen))
            yield NormalizedEvent(
                source_type="pcap",
                flow_id=str(event.get("flow_id", "")),
                src_ip=str(event.get("source_ip", "")),
                dst_ip=str(event.get("dest_ip", "")),
                src_port=int(event.get("source_port", 0) or 0),
                dst_port=int(event.get("dest_port", features.get("Destination Port", 0)) or 0),
                protocol=str(event.get("protocol", features.get("Protocol", "unknown"))),
                direction="outbound",
                packets=fwd_packets + rev_packets,
                bytes=fwd_bytes + rev_bytes,
                duration=max(0.0, last_seen - first_seen),
                first_seen=first_seen,
                last_seen=last_seen,
                tcp_flags=event.get("tcp_flags"),
                raw_reference={"source_path": str(path), "feature_keys": sorted(features)},
            )

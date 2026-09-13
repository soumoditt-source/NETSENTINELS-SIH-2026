import time
from collections import defaultdict


class StateManager:
    """Streaming bounded state manager with TTL eviction."""

    def __init__(self, ttl_seconds=300):
        self.ttl_seconds = ttl_seconds
        self.host_state = defaultdict(lambda: {
            "first_seen": 0,
            "last_seen": 0,
            "destinations": set(),
            "ports": set(),
            "destination_port_pairs": set(),
            "bytes_out": 0,
            "bytes_in": 0,
            "flows": 0,
            "services": set(),
        })
        self.last_eviction = time.time()

    def update_state(self, event):
        now = time.time()
        if now - self.last_eviction > 10:
            self._evict_expired(now)
            self.last_eviction = now

        state = self.host_state[event.src_ip]
        if not state["first_seen"]:
            state["first_seen"] = now
        state["last_seen"] = now
        state["destinations"].add(event.dst_ip)
        state["ports"].add(event.dst_port)
        state["destination_port_pairs"].add((event.dst_ip, event.dst_port))
        if event.direction == "outbound":
            state["bytes_out"] += event.bytes
        else:
            state["bytes_in"] += event.bytes
        state["flows"] += 1
        if event.service_label:
            state["services"].add(event.service_label)
        return dict(state)

    def _evict_expired(self, current_time):
        expired = [ip for ip, data in self.host_state.items() if current_time - data["last_seen"] > self.ttl_seconds]
        for ip in expired:
            del self.host_state[ip]
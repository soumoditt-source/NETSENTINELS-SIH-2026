import time
from collections import defaultdict

class StateManager:
    """
    Streaming bounded state manager with TTL eviction.
    Tracks behavioral features over time without unbounded memory growth.
    """
    def __init__(self, ttl_seconds=300):
        self.ttl_seconds = ttl_seconds
        # Mapping: src_ip -> state dict
        self.host_state = defaultdict(lambda: {
            'last_seen': 0,
            'destinations': set(),
            'ports': set(),
            'bytes_out': 0,
            'bytes_in': 0,
            'flows': 0,
            'services': set()
        })
        self.last_eviction = time.time()
        
    def update_state(self, event):
        now = time.time()
        
        # Evict every 10 seconds to save CPU, not every event
        if now - self.last_eviction > 10:
            self._evict_expired(now)
            self.last_eviction = now
            
        src = event.src_ip
        dst = event.dst_ip
        port = event.dst_port
        
        state = self.host_state[src]
        state['last_seen'] = now
        state['destinations'].add(dst)
        state['ports'].add(port)
        
        if event.direction == 'outbound':
            state['bytes_out'] += event.bytes
        else:
            state['bytes_in'] += event.bytes
            
        state['flows'] += 1
        
        if event.service_label:
            state['services'].add(event.service_label)
            
        return dict(state) # Return a snapshot
        
    def _evict_expired(self, current_time):
        expired = [ip for ip, data in self.host_state.items() 
                   if current_time - data['last_seen'] > self.ttl_seconds]
        for ip in expired:
            del self.host_state[ip]

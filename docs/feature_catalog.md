# Feature catalog

The canonical CIC output preserves numeric flow features while excluding raw
identities from model inputs.

- Flow volume: duration, forward/reverse packets, forward/reverse bytes,
  packet rate, byte rate.
- Packet shape: min/max/mean/std packet lengths and segment sizes.
- Timing: flow inter-arrival statistics and active/idle periods.
- TCP behavior: SYN, ACK, FIN, RST, PSH, and URG counts.
- Behavioral context: capture, anonymized source/destination identity, source
  file, and canonical label.
- DNS metadata: query length, label count, entropy, digit ratio, NXDOMAIN, and
  record type when available.
- Encrypted metadata: TLS/QUIC version, visible SNI/ALPN, fingerprint values,
  size summaries, and timing summaries. Payload content is excluded.

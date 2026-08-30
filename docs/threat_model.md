# Threat model

The monitored network is outside the trust boundary. NetSentinel receives a
one-way copy and must be safe if an input record is malformed or adversarial.
The application protects against accidental egress, arbitrary upload paths,
unbounded PCAP uploads, unsafe Python artifact loading, and untrusted label
inference. It does not claim to defend against a compromised host that forges
all observable metadata.

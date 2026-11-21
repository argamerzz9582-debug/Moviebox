---
name: rex-network-protocol
description: Offline packet capture (PCAP/PCAPNG) inspection, protocol hierarchy mapping, and endpoint dissection using tshark and scapy.
triggers: pcap, pcapng, wireshark, tshark, packet capture, network protocol, traffic analysis
tools_required: tshark, python3
---

# REX Network & Protocol Analysis Skill

## Supported Targets
Authorized `.pcap` (`D4 C3 B2 A1`) and `.pcapng` (`0A 0D 0D 0A`) packet captures and protocol artifacts.

## Headless Workflow
1. **Protocol Hierarchy & Conversations:**
   ```bash
   tshark -r "<capture.pcap>" -q -z io,phs > "$WS/generated/protocol_hierarchy.txt"
   tshark -r "<capture.pcap>" -q -z conv,tcp > "$WS/generated/tcp_conversations.txt"
   ```
2. **DNS, TLS SNI & HTTP Metadata:** Extract queried domains, SNI hostnames, and HTTP request URIs without dumping raw binary streams to stdout.
3. **Encrypted Traffic Rule:** Never claim encrypted TLS/QUIC payloads can be decrypted without explicit session keys or certificates.

## Evidence Rules
Cite exact packet frame numbers (`Frame #142`), stream indices, and timestamps. Redact cookies and credentials.

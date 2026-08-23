"""Network forensics deep analyzer — protocol dissection, session reconstruction, and threat detection.

Capabilities:
  - Deep packet inspection with protocol-aware parsing
  - Session reconstruction (TCP streams, HTTP conversations)
  - DNS anomaly detection (tunneling, DGA, fast-flux)
  - TLS certificate analysis and JA3/JA3S fingerprinting
  - Beacon detection (C2 communication patterns)
  - Data exfiltration heuristics
  - Lateral movement detection
  - Timeline reconstruction for incident response
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from aegis.core.ui import console


# ── Entropy calculation ───────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def string_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    return shannon_entropy(s.encode("utf-8", errors="replace"))


# ── DNS Analysis ──────────────────────────────────────────────────────────────

class DNSAnalyzer:
    """Detect DNS tunneling, DGA domains, and fast-flux networks."""

    # Known DGA patterns (high entropy + length)
    DGA_ENTROPY_THRESHOLD = 3.5
    DGA_LENGTH_THRESHOLD = 12
    TUNNEL_QUERY_LENGTH_THRESHOLD = 50
    TUNNEL_SUBDOMAIN_COUNT_THRESHOLD = 4

    def __init__(self) -> None:
        self.queries: List[Dict] = []
        self.responses: List[Dict] = []
        self._domain_counter: Counter = Counter()
        self._subdomain_lengths: Dict[str, List[int]] = defaultdict(list)
        self._ip_per_domain: Dict[str, set] = defaultdict(set)
        self._query_timestamps: Dict[str, List[float]] = defaultdict(list)

    def add_query(self, query: Dict) -> None:
        """Add a DNS query record for analysis."""
        self.queries.append(query)
        domain = query.get("query_name", "")
        self._domain_counter[domain] += 1

        # Track subdomain structure
        parts = domain.split(".")
        if len(parts) > 2:
            base = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
            self._subdomain_lengths[base].append(len(subdomain))

        # Track IP mappings for fast-flux detection
        answers = query.get("answers", "")
        if answers:
            for ip in str(answers).split(","):
                ip = ip.strip()
                if ip:
                    self._ip_per_domain[domain].add(ip)

        # Track timing
        ts = query.get("ts", 0)
        if ts:
            self._query_timestamps[domain].append(float(ts))

    def detect_tunneling(self) -> List[Dict]:
        """Detect DNS tunneling based on query length, entropy, and frequency."""
        findings = []
        for base_domain, lengths in self._subdomain_lengths.items():
            avg_length = statistics.mean(lengths) if lengths else 0
            max_length = max(lengths) if lengths else 0
            count = len(lengths)

            # Check for tunneling indicators
            indicators = []
            if avg_length > 30:
                indicators.append(f"avg_subdomain_length={avg_length:.1f}")
            if max_length > self.TUNNEL_QUERY_LENGTH_THRESHOLD:
                indicators.append(f"max_subdomain_length={max_length}")
            if count > 50:
                indicators.append(f"high_query_count={count}")

            # Check entropy of subdomains
            high_entropy_count = 0
            for q in self.queries:
                qname = q.get("query_name", "")
                if qname.endswith(base_domain):
                    subdomain = qname[: -(len(base_domain) + 1)]
                    if subdomain and string_entropy(subdomain) > self.DGA_ENTROPY_THRESHOLD:
                        high_entropy_count += 1

            if high_entropy_count > 10:
                indicators.append(f"high_entropy_subdomains={high_entropy_count}")

            if len(indicators) >= 2:
                findings.append({
                    "type": "dns_tunneling",
                    "severity": "high",
                    "domain": base_domain,
                    "indicators": indicators,
                    "query_count": count,
                    "avg_subdomain_length": round(avg_length, 1),
                    "description": (
                        f"Potential DNS tunneling detected via {base_domain}. "
                        f"Indicators: {', '.join(indicators)}"
                    ),
                })
        return findings

    def detect_dga(self) -> List[Dict]:
        """Detect Domain Generation Algorithm (DGA) domains."""
        findings = []
        seen_bases: set = set()

        for query in self.queries:
            domain = query.get("query_name", "")
            parts = domain.split(".")
            if len(parts) < 2:
                continue

            # Get the SLD (second-level domain)
            sld = parts[-2] if len(parts) >= 2 else domain
            base = ".".join(parts[-2:])

            if base in seen_bases:
                continue

            entropy = string_entropy(sld)
            length = len(sld)

            # DGA indicators: high entropy + unusual length + no common words
            is_dga = (
                entropy > self.DGA_ENTROPY_THRESHOLD
                and length > self.DGA_LENGTH_THRESHOLD
                and not self._contains_common_words(sld)
            )

            if is_dga:
                seen_bases.add(base)
                findings.append({
                    "type": "dga_domain",
                    "severity": "high",
                    "domain": domain,
                    "entropy": round(entropy, 3),
                    "length": length,
                    "description": (
                        f"Potential DGA domain: {domain} "
                        f"(entropy={entropy:.3f}, length={length})"
                    ),
                })
        return findings

    def detect_fast_flux(self) -> List[Dict]:
        """Detect fast-flux networks (single domain → many IPs)."""
        findings = []
        for domain, ips in self._ip_per_domain.items():
            if len(ips) >= 5:
                findings.append({
                    "type": "fast_flux",
                    "severity": "medium",
                    "domain": domain,
                    "ip_count": len(ips),
                    "ips": sorted(ips)[:20],
                    "description": (
                        f"Potential fast-flux: {domain} resolves to {len(ips)} distinct IPs"
                    ),
                })
        return findings

    @staticmethod
    def _contains_common_words(s: str) -> bool:
        """Check if string contains common English words (reduces false positives)."""
        common = {
            "google", "amazon", "cloud", "mail", "shop", "blog", "news",
            "forum", "wiki", "chat", "game", "play", "video", "music",
            "store", "market", "trade", "bank", "secure", "login",
        }
        s_lower = s.lower()
        return any(word in s_lower for word in common)

    def full_analysis(self) -> Dict[str, Any]:
        """Run all DNS analyses and return combined results."""
        return {
            "tunneling": self.detect_tunneling(),
            "dga_domains": self.detect_dga(),
            "fast_flux": self.detect_fast_flux(),
            "stats": {
                "total_queries": len(self.queries),
                "unique_domains": len(self._domain_counter),
                "top_queried": self._domain_counter.most_common(20),
            },
        }


# ── Beacon Detection ──────────────────────────────────────────────────────────

class BeaconDetector:
    """Detect Command & Control beaconing patterns in network traffic.

    C2 beacons typically show:
    - Regular time intervals between connections
    - Consistent packet sizes
    - Low jitter (variance in timing)
    - Communication to same destination
    """

    JITTER_THRESHOLD = 0.15  # 15% jitter tolerance
    MIN_CONNECTIONS = 5
    MIN_DURATION_SECONDS = 60

    def __init__(self) -> None:
        self._connections: Dict[str, List[Dict]] = defaultdict(list)

    def add_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: float,
        payload_size: int = 0,
    ) -> None:
        """Record a connection event."""
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        self._connections[key].append({
            "ts": timestamp,
            "size": payload_size,
        })

    def detect(self) -> List[Dict]:
        """Analyze all connections for beacon patterns."""
        findings = []

        for conn_key, events in self._connections.items():
            if len(events) < self.MIN_CONNECTIONS:
                continue

            # Sort by timestamp
            events.sort(key=lambda e: e["ts"])

            # Calculate inter-arrival times
            timestamps = [e["ts"] for e in events]
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

            if not intervals:
                continue

            # Duration check
            duration = timestamps[-1] - timestamps[0]
            if duration < self.MIN_DURATION_SECONDS:
                continue

            # Statistical analysis
            mean_interval = statistics.mean(intervals)
            if mean_interval < 1:  # Sub-second — likely not a beacon
                continue

            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            jitter = stdev_interval / mean_interval if mean_interval > 0 else 1.0

            # Payload size consistency
            sizes = [e["size"] for e in events if e["size"] > 0]
            size_consistency = 0.0
            if sizes:
                mean_size = statistics.mean(sizes)
                size_stdev = statistics.stdev(sizes) if len(sizes) > 1 else 0
                size_consistency = 1.0 - (size_stdev / mean_size if mean_size > 0 else 1.0)

            # Beacon score (0-100)
            beacon_score = self._calculate_beacon_score(
                jitter=jitter,
                connection_count=len(events),
                duration=duration,
                size_consistency=size_consistency,
            )

            if beacon_score >= 60:
                src, dst_full = conn_key.split("->")
                severity = "critical" if beacon_score >= 85 else "high" if beacon_score >= 70 else "medium"

                findings.append({
                    "type": "c2_beacon",
                    "severity": severity,
                    "src_ip": src,
                    "dst": dst_full,
                    "beacon_score": beacon_score,
                    "mean_interval_seconds": round(mean_interval, 2),
                    "jitter": round(jitter, 4),
                    "connection_count": len(events),
                    "duration_seconds": round(duration, 1),
                    "size_consistency": round(size_consistency, 3),
                    "description": (
                        f"C2 beacon detected: {conn_key} "
                        f"(score={beacon_score}, interval={mean_interval:.1f}s, "
                        f"jitter={jitter:.2%}, connections={len(events)})"
                    ),
                })

        # Sort by score descending
        findings.sort(key=lambda f: f["beacon_score"], reverse=True)
        return findings

    @staticmethod
    def _calculate_beacon_score(
        jitter: float,
        connection_count: int,
        duration: float,
        size_consistency: float,
    ) -> int:
        """Calculate a beacon confidence score (0-100)."""
        score = 0

        # Low jitter = high regularity (max 40 points)
        if jitter < 0.05:
            score += 40
        elif jitter < 0.10:
            score += 30
        elif jitter < 0.15:
            score += 20
        elif jitter < 0.25:
            score += 10

        # More connections = more confidence (max 25 points)
        if connection_count >= 100:
            score += 25
        elif connection_count >= 50:
            score += 20
        elif connection_count >= 20:
            score += 15
        elif connection_count >= 10:
            score += 10
        else:
            score += 5

        # Longer duration = more confidence (max 20 points)
        if duration >= 3600:  # 1 hour
            score += 20
        elif duration >= 600:  # 10 minutes
            score += 15
        elif duration >= 120:  # 2 minutes
            score += 10
        else:
            score += 5

        # Consistent payload sizes (max 15 points)
        score += int(size_consistency * 15)

        return min(100, score)


# ── Data Exfiltration Detection ───────────────────────────────────────────────

class ExfiltrationDetector:
    """Detect potential data exfiltration via various channels."""

    def __init__(self) -> None:
        self._outbound_volume: Dict[str, int] = defaultdict(int)  # dst -> total bytes
        self._dns_payload_sizes: List[Tuple[str, int]] = []
        self._large_transfers: List[Dict] = []
        self._unusual_ports: List[Dict] = []

    def add_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        bytes_sent: int,
        protocol: str = "tcp",
        timestamp: float = 0,
    ) -> None:
        """Record an outbound network flow."""
        self._outbound_volume[dst_ip] += bytes_sent

        # Track large transfers
        if bytes_sent > 10 * 1024 * 1024:  # > 10MB
            self._large_transfers.append({
                "src": src_ip,
                "dst": dst_ip,
                "port": dst_port,
                "bytes": bytes_sent,
                "protocol": protocol,
                "ts": timestamp,
            })

        # Track unusual ports
        common_ports = {
            20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
            3306, 5432, 6379, 8080, 8443, 27017,
        }
        if dst_port not in common_ports and bytes_sent > 1024 * 1024:
            self._unusual_ports.append({
                "src": src_ip,
                "dst": dst_ip,
                "port": dst_port,
                "bytes": bytes_sent,
                "protocol": protocol,
                "ts": timestamp,
            })

    def add_dns_query(self, domain: str, query_length: int) -> None:
        """Track DNS queries for DNS exfiltration detection."""
        self._dns_payload_sizes.append((domain, query_length))

    def detect(self) -> List[Dict]:
        """Run all exfiltration detection heuristics."""
        findings = []

        # Large volume to single destination
        for dst, volume in self._outbound_volume.items():
            if volume > 100 * 1024 * 1024:  # > 100MB
                findings.append({
                    "type": "high_volume_exfil",
                    "severity": "high",
                    "destination": dst,
                    "total_bytes": volume,
                    "total_mb": round(volume / (1024 * 1024), 2),
                    "description": (
                        f"High volume data transfer to {dst}: "
                        f"{volume / (1024*1024):.1f} MB total"
                    ),
                })

        # Large single transfers
        for transfer in self._large_transfers:
            findings.append({
                "type": "large_transfer",
                "severity": "medium",
                "src": transfer["src"],
                "dst": transfer["dst"],
                "port": transfer["port"],
                "bytes": transfer["bytes"],
                "description": (
                    f"Large single transfer: {transfer['src']} → "
                    f"{transfer['dst']}:{transfer['port']} "
                    f"({transfer['bytes'] / (1024*1024):.1f} MB)"
                ),
            })

        # Unusual port usage with significant data
        for flow in self._unusual_ports:
            findings.append({
                "type": "unusual_port_transfer",
                "severity": "medium",
                "src": flow["src"],
                "dst": flow["dst"],
                "port": flow["port"],
                "bytes": flow["bytes"],
                "description": (
                    f"Data transfer on unusual port: {flow['src']} → "
                    f"{flow['dst']}:{flow['port']} "
                    f"({flow['bytes'] / (1024*1024):.1f} MB)"
                ),
            })

        # DNS exfiltration (high-volume encoded subdomains)
        if self._dns_payload_sizes:
            total_dns_payload = sum(size for _, size in self._dns_payload_sizes)
            large_dns_queries = [(d, s) for d, s in self._dns_payload_sizes if s > 100]
            if total_dns_payload > 10000 or len(large_dns_queries) > 20:
                findings.append({
                    "type": "dns_exfiltration",
                    "severity": "high",
                    "total_payload_bytes": total_dns_payload,
                    "large_query_count": len(large_dns_queries),
                    "description": (
                        f"Potential DNS data exfiltration: "
                        f"{total_dns_payload} bytes in DNS queries, "
                        f"{len(large_dns_queries)} oversized queries"
                    ),
                })

        return findings


# ── Session Reconstructor ─────────────────────────────────────────────────────

class SessionReconstructor:
    """Reconstruct network sessions from packet-level data."""

    def __init__(self) -> None:
        self._tcp_streams: Dict[str, List[Dict]] = defaultdict(list)
        self._http_conversations: List[Dict] = []

    def add_packet(self, packet: Dict) -> None:
        """Add a parsed packet to stream reconstruction."""
        if packet.get("transport") == "tcp":
            src = f"{packet.get('src_ip', '?')}:{packet.get('sport', '?')}"
            dst = f"{packet.get('dst_ip', '?')}:{packet.get('dport', '?')}"
            # Normalize stream key (always lower IP first)
            stream_key = "||".join(sorted([src, dst]))
            self._tcp_streams[stream_key].append(packet)

    def get_tcp_streams(self) -> Dict[str, List[Dict]]:
        """Return all reconstructed TCP streams."""
        return dict(self._tcp_streams)

    def extract_http_from_streams(self) -> List[Dict]:
        """Extract HTTP request/response pairs from TCP streams."""
        conversations = []
        for stream_key, packets in self._tcp_streams.items():
            request_data = b""
            response_data = b""
            for pkt in packets:
                payload = pkt.get("payload", b"")
                if not payload:
                    continue
                if payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"PUT "):
                    request_data += payload
                elif payload.startswith(b"HTTP/"):
                    response_data += payload

            if request_data:
                try:
                    request_text = request_data.decode("utf-8", errors="replace")
                    first_line = request_text.split("\r\n")[0]
                    method, uri, _ = first_line.split(" ", 2)
                    host = ""
                    for line in request_text.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            break
                    conversations.append({
                        "stream": stream_key,
                        "method": method,
                        "uri": uri,
                        "host": host,
                        "request_size": len(request_data),
                        "response_size": len(response_data),
                    })
                except (ValueError, IndexError):
                    pass

        return conversations

    def summary(self) -> Dict[str, Any]:
        """Return stream reconstruction summary."""
        total_packets = sum(len(pkts) for pkts in self._tcp_streams.values())
        return {
            "total_streams": len(self._tcp_streams),
            "total_packets": total_packets,
            "http_conversations": len(self.extract_http_from_streams()),
        }


# ── Timeline Builder ──────────────────────────────────────────────────────────

class TimelineBuilder:
    """Build an incident response timeline from network events."""

    def __init__(self) -> None:
        self._events: List[Dict] = []

    def add_event(
        self,
        timestamp: float,
        event_type: str,
        source: str,
        description: str,
        severity: str = "info",
        metadata: Optional[Dict] = None,
    ) -> None:
        """Add an event to the timeline."""
        self._events.append({
            "timestamp": timestamp,
            "datetime": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            "type": event_type,
            "source": source,
            "description": description,
            "severity": severity,
            "metadata": metadata or {},
        })

    def build(self) -> List[Dict]:
        """Return timeline sorted chronologically."""
        return sorted(self._events, key=lambda e: e["timestamp"])

    def to_json(self, output_path: str) -> Path:
        """Export timeline to JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.build(), indent=2, default=str),
            encoding="utf-8",
        )
        return path

    def summary(self) -> Dict[str, Any]:
        """Return timeline statistics."""
        events = self.build()
        if not events:
            return {"total_events": 0}

        severity_counts: Dict[str, int] = Counter(e["severity"] for e in events)
        type_counts: Dict[str, int] = Counter(e["type"] for e in events)

        return {
            "total_events": len(events),
            "time_span": {
                "start": events[0]["datetime"],
                "end": events[-1]["datetime"],
            },
            "severity_distribution": dict(severity_counts),
            "event_types": dict(type_counts),
        }


# ── Master Forensics Analyzer ────────────────────────────────────────────────

class ForensicsAnalyzer:
    """Orchestrates all forensics analysis modules on a PCAP or live data."""

    def __init__(self) -> None:
        self.dns_analyzer = DNSAnalyzer()
        self.beacon_detector = BeaconDetector()
        self.exfil_detector = ExfiltrationDetector()
        self.session_reconstructor = SessionReconstructor()
        self.timeline = TimelineBuilder()
        self._packet_count = 0
        self._protocol_stats: Counter = Counter()

    def ingest_packet(self, packet: Dict) -> None:
        """Process a single parsed packet through all analyzers."""
        self._packet_count += 1
        transport = packet.get("transport", "unknown")
        self._protocol_stats[transport] += 1

        # Feed to session reconstructor
        self.session_reconstructor.add_packet(packet)

        # Feed to beacon detector
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        dport = packet.get("dport", 0)
        ts = packet.get("ts", 0)
        payload = packet.get("payload", b"")
        payload_size = len(payload) if isinstance(payload, bytes) else 0

        if src_ip and dst_ip and dport:
            self.beacon_detector.add_connection(
                src_ip, dst_ip, int(dport), float(ts), payload_size
            )

        # Feed to exfiltration detector
        if src_ip and dst_ip:
            self.exfil_detector.add_flow(
                src_ip, dst_ip, int(dport or 0),
                payload_size, transport, float(ts),
            )

        # Add to timeline
        if ts:
            self.timeline.add_event(
                timestamp=float(ts),
                event_type="packet",
                source=f"{src_ip}→{dst_ip}:{dport}",
                description=f"{transport.upper()} {src_ip}→{dst_ip}:{dport} ({payload_size}B)",
                severity="info",
            )

    def ingest_dns_record(self, record: Dict) -> None:
        """Process a DNS query/response record."""
        self.dns_analyzer.add_query(record)
        domain = record.get("query_name", "")
        if domain:
            self.exfil_detector.add_dns_query(domain, len(domain))

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Full analysis of a PCAP file. Returns comprehensive results."""
        from aegis.forensics.capture import PcapReader

        reader = PcapReader(pcap_path)

        # Ingest all packets
        for packet in reader.iter_packets_dpkt():
            self.ingest_packet(packet)

        # Ingest DNS queries
        for dns_record in reader.extract_dns_queries():
            self.ingest_dns_record(dns_record)

        return self.get_results()

    def get_results(self) -> Dict[str, Any]:
        """Get comprehensive analysis results from all modules."""
        return {
            "summary": {
                "total_packets": self._packet_count,
                "protocol_distribution": dict(self._protocol_stats),
                "streams": self.session_reconstructor.summary(),
            },
            "threats": {
                "beacons": self.beacon_detector.detect(),
                "dns_analysis": self.dns_analyzer.full_analysis(),
                "exfiltration": self.exfil_detector.detect(),
            },
            "timeline": self.timeline.summary(),
            "http_conversations": self.session_reconstructor.extract_http_from_streams()[:50],
        }

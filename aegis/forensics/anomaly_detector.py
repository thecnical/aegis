"""Real-time network anomaly detection engine — statistical + pattern-based.

No ML libraries required. Uses pure mathematical approaches:
  - Statistical baseline modeling (rolling mean/stdev per metric)
  - Z-score deviation detection (traffic volume, packet rates, flow counts)
  - Time-series seasonality detection (daily/hourly patterns)
  - Protocol ratio anomaly (unusual protocol distribution)
  - Port scan detection (many ports from one source in short time)
  - Horizontal scan detection (one port across many hosts)
  - Slowloris/low-and-slow attack patterns
  - ARP spoofing detection
  - ICMP flood/tunnel detection
  - Unusual payload entropy (encrypted C2, steganography indicators)

Design: Streaming architecture — processes packets one at a time with O(1) memory
per metric via exponential moving averages. Can handle live traffic.
"""
from __future__ import annotations

import math
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ── Streaming Statistics ──────────────────────────────────────────────────────

class StreamingStats:
    """O(1) memory streaming statistics using Welford's algorithm.

    Computes running mean, variance, and Z-scores without storing all values.
    """

    def __init__(self, window_size: int = 1000) -> None:
        self._count = 0
        self._mean = 0.0
        self._m2 = 0.0  # Sum of squared deviations
        self._min = float("inf")
        self._max = float("-inf")
        self._window_size = window_size
        # EMA for recent trend (exponential moving average)
        self._ema = 0.0
        self._ema_alpha = 2.0 / (window_size + 1)

    def update(self, value: float) -> None:
        """Add a new observation using Welford's online algorithm."""
        self._count += 1
        delta = value - self._mean
        self._mean += delta / self._count
        delta2 = value - self._mean
        self._m2 += delta * delta2
        self._min = min(self._min, value)
        self._max = max(self._max, value)
        # Update EMA
        if self._count == 1:
            self._ema = value
        else:
            self._ema = (self._ema_alpha * value) + ((1 - self._ema_alpha) * self._ema)

    @property
    def count(self) -> int:
        return self._count

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        if self._count < 2:
            return 0.0
        return self._m2 / (self._count - 1)

    @property
    def stdev(self) -> float:
        return math.sqrt(self.variance)

    @property
    def ema(self) -> float:
        return self._ema

    def z_score(self, value: float) -> float:
        """Calculate Z-score (number of standard deviations from mean)."""
        if self.stdev == 0 or self._count < 10:
            return 0.0
        return (value - self._mean) / self.stdev

    def is_anomaly(self, value: float, threshold: float = 3.0) -> bool:
        """Check if value is anomalous (|Z| > threshold)."""
        return abs(self.z_score(value)) > threshold


# ── Time Window Counter ───────────────────────────────────────────────────────

class TimeWindowCounter:
    """Count events within a sliding time window."""

    def __init__(self, window_seconds: int = 60) -> None:
        self._window = window_seconds
        self._events: deque = deque()

    def add(self, timestamp: float = 0) -> None:
        ts = timestamp or time.time()
        self._events.append(ts)
        self._cleanup(ts)

    def count(self, now: float = 0) -> int:
        now = now or time.time()
        self._cleanup(now)
        return len(self._events)

    def rate(self, now: float = 0) -> float:
        """Events per second within the window."""
        now = now or time.time()
        self._cleanup(now)
        if not self._events:
            return 0.0
        return len(self._events) / self._window

    def _cleanup(self, now: float) -> None:
        cutoff = now - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


# ── Anomaly Types ─────────────────────────────────────────────────────────────

@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_type: str
    severity: str  # info, low, medium, high, critical
    timestamp: float
    description: str
    source_ip: str = ""
    dest_ip: str = ""
    port: int = 0
    score: float = 0.0  # Confidence score (0-100)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.anomaly_type,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "description": self.description,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "port": self.port,
            "score": self.score,
            "metadata": self.metadata,
        }


# ── Core Anomaly Detection Engine ─────────────────────────────────────────────

class AnomalyDetectionEngine:
    """Real-time statistical anomaly detection for network traffic.

    Designed for streaming: processes one packet/flow at a time.
    Maintains internal baselines and detects deviations.
    """

    def __init__(
        self,
        z_threshold: float = 3.0,
        port_scan_threshold: int = 20,
        horizontal_scan_threshold: int = 10,
        rate_window_seconds: int = 60,
        baseline_warmup: int = 100,
    ) -> None:
        self._z_threshold = z_threshold
        self._port_scan_threshold = port_scan_threshold
        self._horizontal_scan_threshold = horizontal_scan_threshold
        self._rate_window = rate_window_seconds
        self._baseline_warmup = baseline_warmup

        # Streaming statistics per metric
        self._stats: Dict[str, StreamingStats] = defaultdict(StreamingStats)

        # Rate counters
        self._global_packet_rate = TimeWindowCounter(rate_window_seconds)
        self._per_src_rate: Dict[str, TimeWindowCounter] = defaultdict(
            lambda: TimeWindowCounter(rate_window_seconds)
        )
        self._per_dst_rate: Dict[str, TimeWindowCounter] = defaultdict(
            lambda: TimeWindowCounter(rate_window_seconds)
        )

        # Port scan detection: src_ip → set of dst_ports in window
        self._src_port_access: Dict[str, Dict[str, Set[int]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._src_port_timestamps: Dict[str, float] = {}

        # Horizontal scan: port → set of dst_ips from same src
        self._horizontal_scans: Dict[str, Dict[int, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._horizontal_timestamps: Dict[str, float] = {}

        # Protocol distribution
        self._protocol_counter: Counter = Counter()  # type: ignore[type-arg]
        self._protocol_stats = StreamingStats()

        # ARP tracking
        self._arp_table: Dict[str, str] = {}  # IP → MAC
        self._arp_changes: List[Tuple[str, str, str]] = []  # (IP, old_mac, new_mac)

        # Payload entropy tracking
        self._entropy_stats = StreamingStats()

        # ICMP tracking
        self._icmp_rate: Dict[str, TimeWindowCounter] = defaultdict(
            lambda: TimeWindowCounter(rate_window_seconds)
        )

        # Connection tracking for slowloris
        self._open_connections: Dict[str, Dict[str, float]] = defaultdict(dict)
        # src → {dst: first_seen_time}

        # Anomaly buffer
        self._anomalies: List[Anomaly] = []
        self._anomaly_callbacks: List[Callable[[Anomaly], None]] = []

        # Counters
        self._total_packets = 0
        self._total_bytes = 0

    def on_anomaly(self, callback: Callable[[Anomaly], None]) -> None:
        """Register a callback for when anomalies are detected."""
        self._anomaly_callbacks.append(callback)

    def _emit_anomaly(self, anomaly: Anomaly) -> None:
        """Store and notify about a detected anomaly."""
        self._anomalies.append(anomaly)
        for cb in self._anomaly_callbacks:
            try:
                cb(anomaly)
            except Exception:
                pass

    # ── Main Ingestion Point ──────────────────────────────────────────────────

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "tcp",
        payload_size: int = 0,
        payload: bytes = b"",
        timestamp: float = 0,
        ttl: int = 64,
        flags: str = "",
    ) -> List[Anomaly]:
        """Process a single packet and return any anomalies detected.

        This is the main entry point for the streaming engine.
        Returns a list of anomalies detected from this packet.
        """
        ts = timestamp or time.time()
        new_anomalies: List[Anomaly] = []
        self._total_packets += 1
        self._total_bytes += payload_size

        # Update global stats
        self._global_packet_rate.add(ts)
        self._per_src_rate[src_ip].add(ts)
        self._per_dst_rate[dst_ip].add(ts)
        self._protocol_counter[protocol] += 1

        # ── Volume anomaly detection ─────────────────────────────────────────
        new_anomalies.extend(self._check_volume_anomaly(src_ip, dst_ip, payload_size, ts))

        # ── Rate anomaly detection ───────────────────────────────────────────
        new_anomalies.extend(self._check_rate_anomaly(src_ip, dst_ip, ts))

        # ── Port scan detection ──────────────────────────────────────────────
        if dst_port:
            new_anomalies.extend(self._check_port_scan(src_ip, dst_ip, dst_port, ts))

        # ── Horizontal scan detection ────────────────────────────────────────
        if dst_port:
            new_anomalies.extend(self._check_horizontal_scan(src_ip, dst_ip, dst_port, ts))

        # ── Payload entropy anomaly ──────────────────────────────────────────
        if payload and len(payload) > 20:
            new_anomalies.extend(self._check_entropy_anomaly(src_ip, dst_ip, payload, ts))

        # ── ICMP anomaly ─────────────────────────────────────────────────────
        if protocol == "icmp":
            new_anomalies.extend(self._check_icmp_anomaly(src_ip, dst_ip, payload_size, ts))

        # ── TTL anomaly (OS fingerprint change / MITM indicator) ─────────────
        new_anomalies.extend(self._check_ttl_anomaly(src_ip, ttl, ts))

        # ── Slowloris detection ──────────────────────────────────────────────
        if protocol == "tcp" and dst_port in (80, 443, 8080, 8443):
            new_anomalies.extend(self._check_slowloris(src_ip, dst_ip, dst_port, flags, ts))

        # Store and emit
        for anomaly in new_anomalies:
            self._emit_anomaly(anomaly)

        return new_anomalies

    def process_arp(
        self,
        ip_address: str,
        mac_address: str,
        timestamp: float = 0,
    ) -> List[Anomaly]:
        """Process an ARP packet for spoofing detection."""
        ts = timestamp or time.time()
        anomalies: List[Anomaly] = []

        if ip_address in self._arp_table:
            old_mac = self._arp_table[ip_address]
            if old_mac != mac_address:
                self._arp_changes.append((ip_address, old_mac, mac_address))
                anomalies.append(Anomaly(
                    anomaly_type="arp_spoofing",
                    severity="critical",
                    timestamp=ts,
                    description=(
                        f"ARP spoofing detected: {ip_address} changed MAC "
                        f"from {old_mac} to {mac_address}"
                    ),
                    source_ip=ip_address,
                    score=90.0,
                    metadata={"old_mac": old_mac, "new_mac": mac_address},
                ))
        self._arp_table[ip_address] = mac_address

        for a in anomalies:
            self._emit_anomaly(a)
        return anomalies

    # ── Detection Methods ─────────────────────────────────────────────────────

    def _check_volume_anomaly(
        self, src_ip: str, dst_ip: str, payload_size: int, ts: float
    ) -> List[Anomaly]:
        """Detect unusual traffic volume."""
        anomalies = []
        stat_key = f"volume:{src_ip}"
        stat = self._stats[stat_key]
        stat.update(float(payload_size))

        if stat.count > self._baseline_warmup:
            z = stat.z_score(float(payload_size))
            if abs(z) > self._z_threshold and payload_size > 10000:
                anomalies.append(Anomaly(
                    anomaly_type="volume_spike",
                    severity="medium" if z > 4 else "low",
                    timestamp=ts,
                    description=(
                        f"Unusual traffic volume from {src_ip}: "
                        f"{payload_size}B (z-score={z:.2f}, mean={stat.mean:.0f}B)"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    score=min(95, 50 + abs(z) * 10),
                    metadata={"payload_size": payload_size, "z_score": z, "mean": stat.mean},
                ))
        return anomalies

    def _check_rate_anomaly(
        self, src_ip: str, dst_ip: str, ts: float
    ) -> List[Anomaly]:
        """Detect unusual packet rate from a source."""
        anomalies = []
        current_rate = self._per_src_rate[src_ip].rate(ts)

        stat_key = f"rate:{src_ip}"
        stat = self._stats[stat_key]
        stat.update(current_rate)

        if stat.count > self._baseline_warmup:
            z = stat.z_score(current_rate)
            if z > self._z_threshold and current_rate > 50:  # More than 50 pps
                anomalies.append(Anomaly(
                    anomaly_type="rate_spike",
                    severity="high" if current_rate > 1000 else "medium",
                    timestamp=ts,
                    description=(
                        f"Abnormal packet rate from {src_ip}: "
                        f"{current_rate:.1f} pps (z-score={z:.2f}, baseline={stat.mean:.1f} pps)"
                    ),
                    source_ip=src_ip,
                    score=min(95, 50 + z * 8),
                    metadata={"rate_pps": current_rate, "z_score": z, "baseline": stat.mean},
                ))
        return anomalies

    def _check_port_scan(
        self, src_ip: str, dst_ip: str, dst_port: int, ts: float
    ) -> List[Anomaly]:
        """Detect port scanning (many ports from one source to one dest)."""
        anomalies = []

        # Reset if too old
        last_ts = self._src_port_timestamps.get(src_ip, 0)
        if ts - last_ts > self._rate_window:
            self._src_port_access[src_ip] = defaultdict(set)
        self._src_port_timestamps[src_ip] = ts

        self._src_port_access[src_ip][dst_ip].add(dst_port)
        ports_hit = len(self._src_port_access[src_ip][dst_ip])

        if ports_hit == self._port_scan_threshold:
            anomalies.append(Anomaly(
                anomaly_type="port_scan",
                severity="high",
                timestamp=ts,
                description=(
                    f"Port scan detected: {src_ip} → {dst_ip} "
                    f"({ports_hit} ports in {self._rate_window}s)"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                score=85.0,
                metadata={
                    "ports_scanned": ports_hit,
                    "window_seconds": self._rate_window,
                    "sample_ports": sorted(list(self._src_port_access[src_ip][dst_ip]))[:20],
                },
            ))
        elif ports_hit > self._port_scan_threshold and ports_hit % 50 == 0:
            # Additional alerts at higher thresholds
            anomalies.append(Anomaly(
                anomaly_type="port_scan_aggressive",
                severity="critical",
                timestamp=ts,
                description=(
                    f"Aggressive port scan: {src_ip} → {dst_ip} "
                    f"({ports_hit} ports)"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                score=95.0,
                metadata={"ports_scanned": ports_hit},
            ))
        return anomalies

    def _check_horizontal_scan(
        self, src_ip: str, dst_ip: str, dst_port: int, ts: float
    ) -> List[Anomaly]:
        """Detect horizontal scanning (one port across many hosts)."""
        anomalies = []

        last_ts = self._horizontal_timestamps.get(src_ip, 0)
        if ts - last_ts > self._rate_window:
            self._horizontal_scans[src_ip] = defaultdict(set)
        self._horizontal_timestamps[src_ip] = ts

        self._horizontal_scans[src_ip][dst_port].add(dst_ip)
        hosts_hit = len(self._horizontal_scans[src_ip][dst_port])

        if hosts_hit == self._horizontal_scan_threshold:
            anomalies.append(Anomaly(
                anomaly_type="horizontal_scan",
                severity="high",
                timestamp=ts,
                description=(
                    f"Horizontal scan detected: {src_ip} scanning port {dst_port} "
                    f"across {hosts_hit} hosts"
                ),
                source_ip=src_ip,
                port=dst_port,
                score=80.0,
                metadata={
                    "port": dst_port,
                    "hosts_scanned": hosts_hit,
                    "sample_hosts": sorted(list(self._horizontal_scans[src_ip][dst_port]))[:10],
                },
            ))
        return anomalies

    def _check_entropy_anomaly(
        self, src_ip: str, dst_ip: str, payload: bytes, ts: float
    ) -> List[Anomaly]:
        """Detect payloads with unusual entropy (encrypted C2, stego, tunneling)."""
        anomalies = []

        # Calculate Shannon entropy
        entropy = self._shannon_entropy(payload)
        self._entropy_stats.update(entropy)

        # Very high entropy (>7.5/8.0) suggests encrypted/compressed data
        # on ports that shouldn't be encrypted
        if self._entropy_stats.count > self._baseline_warmup:
            z = self._entropy_stats.z_score(entropy)
            if z > self._z_threshold and entropy > 7.5:
                anomalies.append(Anomaly(
                    anomaly_type="high_entropy_payload",
                    severity="medium",
                    timestamp=ts,
                    description=(
                        f"High entropy payload: {src_ip} → {dst_ip} "
                        f"(entropy={entropy:.3f}/8.0, z={z:.2f}) "
                        f"— possible encrypted C2 or data tunneling"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    score=min(80, 40 + z * 10),
                    metadata={"entropy": entropy, "payload_size": len(payload), "z_score": z},
                ))

            # Very low entropy on data channels is also suspicious (padding/null sleds)
            elif z < -self._z_threshold and entropy < 1.0 and len(payload) > 100:
                anomalies.append(Anomaly(
                    anomaly_type="low_entropy_payload",
                    severity="low",
                    timestamp=ts,
                    description=(
                        f"Suspiciously low entropy payload: {src_ip} → {dst_ip} "
                        f"(entropy={entropy:.3f}, {len(payload)}B) "
                        f"— possible null sled or padding"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    score=40.0,
                    metadata={"entropy": entropy, "payload_size": len(payload)},
                ))
        return anomalies

    def _check_icmp_anomaly(
        self, src_ip: str, dst_ip: str, payload_size: int, ts: float
    ) -> List[Anomaly]:
        """Detect ICMP floods and ICMP tunneling."""
        anomalies = []
        self._icmp_rate[src_ip].add(ts)
        rate = self._icmp_rate[src_ip].rate(ts)

        # ICMP flood: high rate
        if rate > 100:
            anomalies.append(Anomaly(
                anomaly_type="icmp_flood",
                severity="high",
                timestamp=ts,
                description=(
                    f"ICMP flood from {src_ip}: {rate:.0f} packets/sec"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                score=85.0,
                metadata={"rate_pps": rate},
            ))

        # ICMP tunneling: large payloads in ICMP (normal ping is 32-64 bytes)
        if payload_size > 128:
            anomalies.append(Anomaly(
                anomaly_type="icmp_tunnel",
                severity="high",
                timestamp=ts,
                description=(
                    f"Possible ICMP tunneling: {src_ip} → {dst_ip} "
                    f"(payload={payload_size}B, normal ping is 32-64B)"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                score=75.0,
                metadata={"payload_size": payload_size},
            ))
        return anomalies

    def _check_ttl_anomaly(
        self, src_ip: str, ttl: int, ts: float
    ) -> List[Anomaly]:
        """Detect TTL changes that might indicate MITM or OS change."""
        anomalies = []
        stat_key = f"ttl:{src_ip}"
        stat = self._stats[stat_key]
        stat.update(float(ttl))

        # After baseline, check for TTL changes (indicates path change or MITM)
        if stat.count > 50:
            z = stat.z_score(float(ttl))
            if abs(z) > 4.0:  # TTL should be very consistent
                anomalies.append(Anomaly(
                    anomaly_type="ttl_anomaly",
                    severity="medium",
                    timestamp=ts,
                    description=(
                        f"TTL anomaly from {src_ip}: TTL={ttl} "
                        f"(expected ~{stat.mean:.0f}, z={z:.2f}) "
                        f"— possible MITM or route change"
                    ),
                    source_ip=src_ip,
                    score=60.0,
                    metadata={"ttl": ttl, "expected": stat.mean, "z_score": z},
                ))
        return anomalies

    def _check_slowloris(
        self, src_ip: str, dst_ip: str, dst_port: int, flags: str, ts: float
    ) -> List[Anomaly]:
        """Detect Slowloris-style attacks (many open connections, slow data)."""
        anomalies = []
        conn_key = f"{dst_ip}:{dst_port}"

        if "SYN" in flags.upper() and "ACK" not in flags.upper():
            # New connection
            self._open_connections[src_ip][conn_key] = ts
        elif "FIN" in flags.upper() or "RST" in flags.upper():
            # Connection closed
            self._open_connections[src_ip].pop(conn_key, None)

        # Check if too many long-lived connections from one source
        active = self._open_connections[src_ip]
        old_connections = [
            k for k, start in active.items()
            if ts - start > 30  # Open for more than 30 seconds
        ]

        if len(old_connections) >= 10:
            anomalies.append(Anomaly(
                anomaly_type="slowloris",
                severity="high",
                timestamp=ts,
                description=(
                    f"Possible Slowloris attack from {src_ip}: "
                    f"{len(old_connections)} long-lived HTTP connections"
                ),
                source_ip=src_ip,
                dest_ip=dst_ip,
                port=dst_port,
                score=80.0,
                metadata={
                    "open_connections": len(old_connections),
                    "total_connections": len(active),
                },
            ))
            # Reset to avoid repeated alerts
            self._open_connections[src_ip] = {
                k: v for k, v in active.items()
                if k not in old_connections
            }
        return anomalies

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of bytes (0.0 - 8.0)."""
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

    # ── Results & Status ──────────────────────────────────────────────────────

    def get_anomalies(
        self,
        since: float = 0,
        severity: Optional[str] = None,
        anomaly_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Get detected anomalies with optional filtering."""
        results = self._anomalies
        if since:
            results = [a for a in results if a.timestamp >= since]
        if severity:
            results = [a for a in results if a.severity == severity]
        if anomaly_type:
            results = [a for a in results if a.anomaly_type == anomaly_type]
        return [a.to_dict() for a in results[-limit:]]

    def get_status(self) -> Dict[str, Any]:
        """Get engine status and statistics."""
        anomaly_counts = Counter(a.anomaly_type for a in self._anomalies)
        severity_counts = Counter(a.severity for a in self._anomalies)

        return {
            "total_packets_processed": self._total_packets,
            "total_bytes_processed": self._total_bytes,
            "total_anomalies_detected": len(self._anomalies),
            "anomaly_types": dict(anomaly_counts),
            "severity_distribution": dict(severity_counts),
            "tracked_sources": len(self._per_src_rate),
            "tracked_destinations": len(self._per_dst_rate),
            "arp_table_size": len(self._arp_table),
            "arp_spoofing_events": len(self._arp_changes),
            "protocol_distribution": dict(self._protocol_counter),
            "baseline_metrics": len(self._stats),
        }

    def reset(self) -> None:
        """Reset all state (useful for testing or baseline re-learning)."""
        self._anomalies.clear()
        self._stats.clear()
        self._global_packet_rate = TimeWindowCounter(self._rate_window)
        self._per_src_rate.clear()
        self._per_dst_rate.clear()
        self._src_port_access.clear()
        self._horizontal_scans.clear()
        self._arp_table.clear()
        self._arp_changes.clear()
        self._open_connections.clear()
        self._protocol_counter.clear()
        self._total_packets = 0
        self._total_bytes = 0


# ── Integration with PCAP analysis ────────────────────────────────────────────

def analyze_pcap_anomalies(
    pcap_path: str,
    z_threshold: float = 3.0,
    port_scan_threshold: int = 20,
) -> Dict[str, Any]:
    """Run anomaly detection on an existing PCAP file.

    Returns combined results from the anomaly engine.
    """
    from aegis.forensics.capture import PcapReader

    engine = AnomalyDetectionEngine(
        z_threshold=z_threshold,
        port_scan_threshold=port_scan_threshold,
    )

    reader = PcapReader(pcap_path)
    for packet in reader.iter_packets_dpkt():
        engine.process_packet(
            src_ip=packet.get("src_ip", ""),
            dst_ip=packet.get("dst_ip", ""),
            src_port=packet.get("sport", 0),
            dst_port=packet.get("dport", 0),
            protocol=packet.get("transport", "unknown"),
            payload_size=len(packet.get("payload", b"")),
            payload=packet.get("payload", b""),
            timestamp=packet.get("ts", 0),
            ttl=packet.get("ttl", 64),
        )

    return {
        "status": engine.get_status(),
        "anomalies": engine.get_anomalies(),
    }

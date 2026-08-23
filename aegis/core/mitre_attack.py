"""MITRE ATT&CK framework mapping — auto-maps findings to techniques and tactics.

Maps vulnerability findings, forensic observations, and anomaly detections to
MITRE ATT&CK Enterprise techniques (v14+). Provides:
  - Automatic finding → technique mapping via keyword/category rules
  - Kill chain coverage visualization
  - Technique enrichment (ID, name, tactic, description, URL)
  - Attack narrative generation
  - Coverage gap analysis
  - Tactic-based prioritization

Reference: https://attack.mitre.org/techniques/enterprise/
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


# ── ATT&CK Tactics (Kill Chain Phases) ────────────────────────────────────────

TACTICS: Dict[str, Dict[str, Any]] = {
    "TA0043": {"name": "Reconnaissance", "shortname": "recon", "order": 1},
    "TA0042": {"name": "Resource Development", "shortname": "resource-dev", "order": 2},
    "TA0001": {"name": "Initial Access", "shortname": "initial-access", "order": 3},
    "TA0002": {"name": "Execution", "shortname": "execution", "order": 4},
    "TA0003": {"name": "Persistence", "shortname": "persistence", "order": 5},
    "TA0004": {"name": "Privilege Escalation", "shortname": "priv-esc", "order": 6},
    "TA0005": {"name": "Defense Evasion", "shortname": "defense-evasion", "order": 7},
    "TA0006": {"name": "Credential Access", "shortname": "cred-access", "order": 8},
    "TA0007": {"name": "Discovery", "shortname": "discovery", "order": 9},
    "TA0008": {"name": "Lateral Movement", "shortname": "lateral-movement", "order": 10},
    "TA0009": {"name": "Collection", "shortname": "collection", "order": 11},
    "TA0011": {"name": "Command and Control", "shortname": "c2", "order": 12},
    "TA0010": {"name": "Exfiltration", "shortname": "exfil", "order": 13},
    "TA0040": {"name": "Impact", "shortname": "impact", "order": 14},
}


# ── ATT&CK Techniques Database ───────────────────────────────────────────────
# Curated subset of most relevant techniques for web/network pentesting

@dataclass
class Technique:
    technique_id: str
    name: str
    tactic_ids: List[str]
    description: str
    url: str
    detection: str = ""
    platforms: List[str] = field(default_factory=lambda: ["Linux", "Windows", "macOS"])
    data_sources: List[str] = field(default_factory=list)

    @property
    def tactics(self) -> List[str]:
        return [str(TACTICS[tid]["name"]) for tid in self.tactic_ids if tid in TACTICS]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactics": self.tactics,
            "tactic_ids": self.tactic_ids,
            "description": self.description,
            "url": self.url,
            "detection": self.detection,
            "platforms": self.platforms,
        }


# Comprehensive technique database
TECHNIQUES: Dict[str, Technique] = {}


def _t(tid: str, name: str, tactics: List[str], desc: str, detection: str = "") -> None:
    """Helper to register a technique."""
    TECHNIQUES[tid] = Technique(
        technique_id=tid,
        name=name,
        tactic_ids=tactics,
        description=desc,
        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        detection=detection,
    )


# ── Reconnaissance ────────────────────────────────────────────────────────────
_t("T1595", "Active Scanning", ["TA0043"], "Adversary probing infrastructure to gather information.", "Monitor for suspicious scan traffic, unusual connection patterns.")
_t("T1595.001", "Scanning IP Blocks", ["TA0043"], "Scanning IP ranges to identify live hosts and open ports.", "Network IDS/IPS, firewall logs showing sequential connection attempts.")
_t("T1595.002", "Vulnerability Scanning", ["TA0043"], "Using automated tools to scan for vulnerabilities.", "Web server logs, IDS signatures for known scanner user-agents.")
_t("T1592", "Gather Victim Host Information", ["TA0043"], "Gathering information about victim hosts (hardware, software, configurations).", "")
_t("T1592.002", "Software", ["TA0043"], "Gathering information about software on victim hosts.", "")
_t("T1589", "Gather Victim Identity Information", ["TA0043"], "Collecting victim identity data (credentials, emails, names).", "")
_t("T1590", "Gather Victim Network Information", ["TA0043"], "Gathering victim network topology, DNS, domain info.", "")
_t("T1590.002", "DNS", ["TA0043"], "Querying DNS to gather victim network information.", "")
_t("T1593", "Search Open Websites/Domains", ["TA0043"], "Searching publicly available websites for victim information.", "")
_t("T1596", "Search Open Technical Databases", ["TA0043"], "Searching technical databases (WHOIS, DNS, cert transparency) for info.", "")
_t("T1596.003", "Digital Certificates", ["TA0043"], "Searching certificate transparency logs and cert databases.", "")

# ── Initial Access ────────────────────────────────────────────────────────────
_t("T1190", "Exploit Public-Facing Application", ["TA0001"], "Exploiting vulnerabilities in internet-facing applications (SQLi, RCE, etc.).", "Application logs, WAF alerts, IDS/IPS signatures.")
_t("T1133", "External Remote Services", ["TA0001"], "Using remote services (VPN, RDP, SSH) for initial access.", "Authentication logs, VPN connection logs.")
_t("T1078", "Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"], "Using stolen or compromised credentials.", "Login audit logs, impossible travel detection.")
_t("T1078.001", "Default Accounts", ["TA0001", "TA0003", "TA0004"], "Using default credentials that haven't been changed.", "Authentication logs for default usernames.")
_t("T1189", "Drive-by Compromise", ["TA0001"], "Gaining access through users visiting compromised websites.", "Browser exploit detection, network traffic analysis.")
_t("T1566", "Phishing", ["TA0001"], "Sending phishing messages to gain access.", "Email gateway logs, user reports.")

# ── Execution ─────────────────────────────────────────────────────────────────
_t("T1059", "Command and Scripting Interpreter", ["TA0002"], "Using command-line interfaces and scripting for execution.", "Process monitoring, command-line auditing.")
_t("T1059.001", "PowerShell", ["TA0002"], "Using PowerShell for execution.", "PowerShell logging, script block logging.")
_t("T1059.004", "Unix Shell", ["TA0002"], "Using Unix shell commands for execution.", "Auditd, bash history, process monitoring.")
_t("T1203", "Exploitation for Client Execution", ["TA0002"], "Exploiting software vulnerabilities for code execution.", "Application crash reports, exploit detection signatures.")
_t("T1059.007", "JavaScript", ["TA0002"], "Using JavaScript for execution (XSS, Node.js).", "Browser security events, CSP violation reports.")

# ── Persistence ───────────────────────────────────────────────────────────────
_t("T1505", "Server Software Component", ["TA0003"], "Installing malicious server components (web shells, plugins).", "File integrity monitoring, web server log analysis.")
_t("T1505.003", "Web Shell", ["TA0003"], "Installing web shells for persistent access.", "File integrity monitoring, unusual web server child processes.")
_t("T1136", "Create Account", ["TA0003"], "Creating new accounts for persistence.", "Account creation audit events.")
_t("T1098", "Account Manipulation", ["TA0003", "TA0004"], "Manipulating accounts (adding creds, modifying permissions).", "Account modification audit logs.")

# ── Privilege Escalation ──────────────────────────────────────────────────────
_t("T1068", "Exploitation for Privilege Escalation", ["TA0004"], "Exploiting software vulnerabilities to elevate privileges.", "Process monitoring, exploit detection.")
_t("T1548", "Abuse Elevation Control Mechanism", ["TA0004", "TA0005"], "Bypassing elevation controls (sudo, UAC, setuid).", "Process monitoring, sudo logs.")
_t("T1548.001", "Setuid and Setgid", ["TA0004", "TA0005"], "Abusing setuid/setgid binaries for privilege escalation.", "File system monitoring, process execution tracking.")

# ── Defense Evasion ───────────────────────────────────────────────────────────
_t("T1027", "Obfuscated Files or Information", ["TA0005"], "Using obfuscation to hide malicious content.", "File analysis, entropy detection, deobfuscation tools.")
_t("T1070", "Indicator Removal", ["TA0005"], "Removing evidence of compromise (log deletion, timestomping).", "Log integrity monitoring, SIEM correlation.")
_t("T1562", "Impair Defenses", ["TA0005"], "Disabling or modifying security tools and logging.", "Security tool status monitoring, process termination alerts.")
_t("T1036", "Masquerading", ["TA0005"], "Making malicious items appear legitimate.", "File hash verification, digital signature validation.")

# ── Credential Access ─────────────────────────────────────────────────────────
_t("T1110", "Brute Force", ["TA0006"], "Attempting many passwords/credentials to gain access.", "Account lockout events, failed login spikes.")
_t("T1110.001", "Password Guessing", ["TA0006"], "Guessing passwords based on common patterns.", "Failed authentication logs.")
_t("T1110.003", "Password Spraying", ["TA0006"], "Trying common passwords against many accounts.", "Distributed failed login detection.")
_t("T1557", "Adversary-in-the-Middle", ["TA0006", "TA0009"], "Intercepting network communications (ARP spoofing, SSL stripping).", "ARP cache monitoring, certificate pinning violations.")
_t("T1557.002", "ARP Cache Poisoning", ["TA0006", "TA0009"], "Poisoning ARP caches to redirect traffic.", "ARP table monitoring, gratuitous ARP detection.")
_t("T1552", "Unsecured Credentials", ["TA0006"], "Searching for credentials in files, registries, or memory.", "File access monitoring, credential store access auditing.")
_t("T1552.001", "Credentials In Files", ["TA0006"], "Finding credentials stored in plaintext files.", "File access auditing, DLP tools.")
_t("T1558", "Steal or Forge Kerberos Tickets", ["TA0006"], "Attacking Kerberos for credential theft (Kerberoasting, Golden Ticket).", "Kerberos TGS request monitoring, anomalous ticket patterns.")
_t("T1558.003", "Kerberoasting", ["TA0006"], "Requesting Kerberos service tickets to crack offline.", "Unusual TGS requests, service account authentication patterns.")
_t("T1539", "Steal Web Session Cookie", ["TA0006"], "Stealing session cookies for unauthorized access.", "Cookie security flags monitoring, session anomaly detection.")
_t("T1556", "Modify Authentication Process", ["TA0006", "TA0005"], "Modifying authentication mechanisms for credential access.", "Authentication module integrity monitoring.")

# ── Discovery ─────────────────────────────────────────────────────────────────
_t("T1046", "Network Service Discovery", ["TA0007"], "Scanning for services running on remote hosts (port scanning).", "Network IDS, internal firewall logs.")
_t("T1018", "Remote System Discovery", ["TA0007"], "Discovering other systems on the network (ping sweep, ARP scan).", "Internal network monitoring, ARP request patterns.")
_t("T1082", "System Information Discovery", ["TA0007"], "Gathering system information (OS, hardware, patches).", "Process monitoring, API call tracking.")
_t("T1087", "Account Discovery", ["TA0007"], "Enumerating accounts on a system or domain.", "Account enumeration audit events.")
_t("T1087.002", "Domain Account", ["TA0007"], "Enumerating domain accounts and groups.", "LDAP query monitoring, AD audit logs.")
_t("T1069", "Permission Groups Discovery", ["TA0007"], "Discovering permission groups and memberships.", "LDAP/AD audit logs.")
_t("T1083", "File and Directory Discovery", ["TA0007"], "Discovering files and directories (directory bruting/fuzzing).", "Web server access logs, file system auditing.")
_t("T1135", "Network Share Discovery", ["TA0007"], "Discovering SMB/NFS shares on the network.", "SMB audit logs, network monitoring.")

# ── Lateral Movement ──────────────────────────────────────────────────────────
_t("T1021", "Remote Services", ["TA0008"], "Using remote services (SSH, RDP, SMB) for lateral movement.", "Authentication logs, network connection monitoring.")
_t("T1021.001", "Remote Desktop Protocol", ["TA0008"], "Using RDP for lateral movement.", "RDP connection logs, network traffic analysis.")
_t("T1021.002", "SMB/Windows Admin Shares", ["TA0008"], "Using SMB shares for lateral movement.", "SMB audit logs, administrative share access monitoring.")
_t("T1210", "Exploitation of Remote Services", ["TA0008"], "Exploiting remote services for lateral movement.", "Network IDS/IPS, service crash monitoring.")
_t("T1550", "Use Alternate Authentication Material", ["TA0008", "TA0005"], "Using non-standard auth (pass-the-hash, pass-the-ticket).", "Authentication anomaly detection, NTLM relay detection.")

# ── Collection ────────────────────────────────────────────────────────────────
_t("T1005", "Data from Local System", ["TA0009"], "Collecting sensitive data from local file systems.", "File access monitoring, DLP tools.")
_t("T1039", "Data from Network Shared Drive", ["TA0009"], "Collecting data from network shares.", "Share access auditing, file access patterns.")
_t("T1185", "Browser Session Hijacking", ["TA0009"], "Hijacking browser sessions to access web applications.", "Session token monitoring, concurrent session detection.")

# ── Command and Control ───────────────────────────────────────────────────────
_t("T1071", "Application Layer Protocol", ["TA0011"], "Using application protocols (HTTP, DNS, SMTP) for C2.", "Network traffic analysis, protocol anomaly detection.")
_t("T1071.001", "Web Protocols", ["TA0011"], "Using HTTP/HTTPS for C2 communication.", "HTTP traffic analysis, beacon detection.")
_t("T1071.004", "DNS", ["TA0011"], "Using DNS for C2 communication (DNS tunneling).", "DNS query analysis, entropy detection, query length monitoring.")
_t("T1573", "Encrypted Channel", ["TA0011"], "Using encryption for C2 to evade detection.", "TLS inspection, JA3 fingerprinting, certificate analysis.")
_t("T1572", "Protocol Tunneling", ["TA0011"], "Tunneling C2 within other protocols (ICMP, DNS).", "Protocol analysis, payload size anomalies.")
_t("T1095", "Non-Application Layer Protocol", ["TA0011"], "Using non-standard protocols (ICMP, raw TCP) for C2.", "Network flow analysis, protocol ratio monitoring.")
_t("T1571", "Non-Standard Port", ["TA0011"], "Using non-standard ports for C2.", "Network traffic baseline comparison, unusual port usage.")
_t("T1568", "Dynamic Resolution", ["TA0011"], "Using dynamic DNS or DGA for C2 infrastructure.", "DNS monitoring, DGA detection algorithms.")
_t("T1568.002", "Domain Generation Algorithms", ["TA0011"], "Using DGA to generate C2 domains.", "DNS query entropy analysis, NXDomain rate monitoring.")
_t("T1090", "Proxy", ["TA0011"], "Using proxy servers for C2 communication.", "Network flow analysis, proxy log correlation.")
_t("T1102", "Web Service", ["TA0011"], "Using legitimate web services (Pastebin, social media) for C2.", "URL reputation checking, traffic to unusual services.")

# ── Exfiltration ──────────────────────────────────────────────────────────────
_t("T1048", "Exfiltration Over Alternative Protocol", ["TA0010"], "Exfiltrating data over non-C2 protocols (DNS, ICMP).", "Outbound traffic analysis, DNS query volume monitoring.")
_t("T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", ["TA0010"], "Exfiltrating encrypted data over alternative protocols.", "Encrypted traffic to unusual destinations.")
_t("T1041", "Exfiltration Over C2 Channel", ["TA0010"], "Exfiltrating data over the existing C2 channel.", "Outbound data volume monitoring, session size analysis.")
_t("T1567", "Exfiltration Over Web Service", ["TA0010"], "Exfiltrating data via cloud storage or web services.", "Upload monitoring, cloud API access logs.")
_t("T1020", "Automated Exfiltration", ["TA0010"], "Automatically exfiltrating collected data.", "Network volume baselines, scheduled transfer detection.")

# ── Impact ────────────────────────────────────────────────────────────────────
_t("T1499", "Endpoint Denial of Service", ["TA0040"], "Causing denial of service on endpoints.", "Service availability monitoring, resource utilization alerts.")
_t("T1499.002", "Service Exhaustion Flood", ["TA0040"], "Flooding services to cause denial.", "Connection rate monitoring, SYN flood detection.")
_t("T1498", "Network Denial of Service", ["TA0040"], "Causing network-level denial of service.", "Network traffic volume monitoring, DDoS detection.")
_t("T1491", "Defacement", ["TA0040"], "Modifying visual content of websites.", "File integrity monitoring, web content hash checking.")
_t("T1565", "Data Manipulation", ["TA0040"], "Manipulating data to affect business processes.", "Data integrity monitoring, transaction auditing.")
_t("T1486", "Data Encrypted for Impact", ["TA0040"], "Encrypting data for ransom (ransomware).", "File system monitoring, mass file rename detection.")


# ── Mapping Rules ─────────────────────────────────────────────────────────────
# Rules that map finding characteristics to techniques

@dataclass
class MappingRule:
    """A rule that maps a finding characteristic to ATT&CK techniques."""
    rule_id: str
    techniques: List[str]  # Technique IDs
    match_type: str  # "keyword", "category", "source", "severity_category", "regex"
    match_value: str
    confidence: float = 0.7  # 0.0-1.0 how confident this mapping is
    description: str = ""


# Comprehensive mapping rules
MAPPING_RULES: List[MappingRule] = [
    # ── SQL Injection → Exploit Public-Facing App ──────────────────────────────
    MappingRule("sql-1", ["T1190"], "keyword", "sql injection", 0.95, "SQL injection exploits public-facing applications"),
    MappingRule("sql-2", ["T1190"], "keyword", "sqli", 0.95),
    MappingRule("sql-3", ["T1190"], "keyword", "sqlmap", 0.90),
    MappingRule("sql-4", ["T1190", "T1005"], "keyword", "database", 0.60),

    # ── XSS → Client Execution + Cookie Theft ──────────────────────────────────
    MappingRule("xss-1", ["T1059.007", "T1185", "T1539"], "keyword", "xss", 0.90),
    MappingRule("xss-2", ["T1059.007", "T1185"], "keyword", "cross-site scripting", 0.90),
    MappingRule("xss-3", ["T1059.007"], "keyword", "reflected xss", 0.85),
    MappingRule("xss-4", ["T1059.007", "T1505"], "keyword", "stored xss", 0.90),

    # ── RCE / Command Injection ────────────────────────────────────────────────
    MappingRule("rce-1", ["T1190", "T1059"], "keyword", "remote code execution", 0.95),
    MappingRule("rce-2", ["T1190", "T1059.004"], "keyword", "command injection", 0.95),
    MappingRule("rce-3", ["T1190", "T1059"], "keyword", "rce", 0.90),
    MappingRule("rce-4", ["T1059.004"], "keyword", "shell", 0.50),

    # ── LFI / Path Traversal ───────────────────────────────────────────────────
    MappingRule("lfi-1", ["T1083", "T1005"], "keyword", "local file inclusion", 0.90),
    MappingRule("lfi-2", ["T1083", "T1005"], "keyword", "lfi", 0.85),
    MappingRule("lfi-3", ["T1083", "T1005"], "keyword", "path traversal", 0.90),
    MappingRule("lfi-4", ["T1083"], "keyword", "directory traversal", 0.85),

    # ── SSRF ───────────────────────────────────────────────────────────────────
    MappingRule("ssrf-1", ["T1190", "T1090"], "keyword", "ssrf", 0.90),
    MappingRule("ssrf-2", ["T1190", "T1090"], "keyword", "server-side request forgery", 0.90),

    # ── Authentication / Brute Force ───────────────────────────────────────────
    MappingRule("auth-1", ["T1110"], "keyword", "brute force", 0.90),
    MappingRule("auth-2", ["T1110.001"], "keyword", "password guessing", 0.85),
    MappingRule("auth-3", ["T1110.003"], "keyword", "password spraying", 0.90),
    MappingRule("auth-4", ["T1078.001"], "keyword", "default credentials", 0.90),
    MappingRule("auth-5", ["T1078.001"], "keyword", "default password", 0.85),
    MappingRule("auth-6", ["T1110"], "keyword", "hydra", 0.80),
    MappingRule("auth-7", ["T1552.001"], "keyword", "credentials in file", 0.85),
    MappingRule("auth-8", ["T1552"], "keyword", "hardcoded credential", 0.85),

    # ── Port/Network Scanning ──────────────────────────────────────────────────
    MappingRule("scan-1", ["T1046", "T1595.001"], "keyword", "port scan", 0.85),
    MappingRule("scan-2", ["T1595.001"], "keyword", "nmap", 0.70),
    MappingRule("scan-3", ["T1046"], "keyword", "open port", 0.60),
    MappingRule("scan-4", ["T1018"], "keyword", "ping sweep", 0.80),
    MappingRule("scan-5", ["T1595.002"], "keyword", "nuclei", 0.75),
    MappingRule("scan-6", ["T1595.002"], "keyword", "vulnerability scan", 0.80),

    # ── Discovery / Enumeration ────────────────────────────────────────────────
    MappingRule("disc-1", ["T1590.002"], "keyword", "dns enumeration", 0.80),
    MappingRule("disc-2", ["T1590.002"], "keyword", "subdomain", 0.75),
    MappingRule("disc-3", ["T1083"], "keyword", "directory brut", 0.80),
    MappingRule("disc-4", ["T1083"], "keyword", "feroxbuster", 0.75),
    MappingRule("disc-5", ["T1083"], "keyword", "discovered path", 0.70),
    MappingRule("disc-6", ["T1135"], "keyword", "smb share", 0.85),
    MappingRule("disc-7", ["T1087.002"], "keyword", "domain account", 0.80),
    MappingRule("disc-8", ["T1087.002"], "keyword", "ldap", 0.70),
    MappingRule("disc-9", ["T1087"], "keyword", "user enumeration", 0.80),
    MappingRule("disc-10", ["T1592.002"], "keyword", "software version", 0.60),
    MappingRule("disc-11", ["T1592.002"], "keyword", "fingerprint", 0.55),

    # ── Active Directory ───────────────────────────────────────────────────────
    MappingRule("ad-1", ["T1558.003"], "keyword", "kerberoast", 0.95),
    MappingRule("ad-2", ["T1087.002", "T1069"], "keyword", "bloodhound", 0.85),
    MappingRule("ad-3", ["T1087.002"], "keyword", "crackmapexec", 0.80),
    MappingRule("ad-4", ["T1550"], "keyword", "pass-the-hash", 0.95),
    MappingRule("ad-5", ["T1550"], "keyword", "pass the hash", 0.95),
    MappingRule("ad-6", ["T1021.002"], "keyword", "psexec", 0.85),

    # ── Web Shells / Persistence ───────────────────────────────────────────────
    MappingRule("persist-1", ["T1505.003"], "keyword", "web shell", 0.95),
    MappingRule("persist-2", ["T1505.003"], "keyword", "webshell", 0.95),
    MappingRule("persist-3", ["T1136"], "keyword", "new account", 0.70),
    MappingRule("persist-4", ["T1098"], "keyword", "privilege added", 0.75),

    # ── C2 / Beaconing ─────────────────────────────────────────────────────────
    MappingRule("c2-1", ["T1071.001"], "keyword", "c2 beacon", 0.95),
    MappingRule("c2-2", ["T1071.004"], "keyword", "dns tunneling", 0.95),
    MappingRule("c2-3", ["T1568.002"], "keyword", "dga", 0.90),
    MappingRule("c2-4", ["T1572"], "keyword", "icmp tunnel", 0.90),
    MappingRule("c2-5", ["T1095"], "keyword", "icmp flood", 0.70),
    MappingRule("c2-6", ["T1573"], "keyword", "encrypted channel", 0.75),
    MappingRule("c2-7", ["T1571"], "keyword", "unusual port", 0.70),

    # ── Exfiltration ───────────────────────────────────────────────────────────
    MappingRule("exfil-1", ["T1048"], "keyword", "exfiltration", 0.90),
    MappingRule("exfil-2", ["T1048"], "keyword", "data exfil", 0.90),
    MappingRule("exfil-3", ["T1041"], "keyword", "high volume", 0.60),
    MappingRule("exfil-4", ["T1048"], "keyword", "dns exfiltration", 0.95),

    # ── DoS / Impact ───────────────────────────────────────────────────────────
    MappingRule("dos-1", ["T1499.002"], "keyword", "slowloris", 0.90),
    MappingRule("dos-2", ["T1499"], "keyword", "denial of service", 0.85),
    MappingRule("dos-3", ["T1498"], "keyword", "flood", 0.65),

    # ── ARP / MitM ─────────────────────────────────────────────────────────────
    MappingRule("mitm-1", ["T1557.002"], "keyword", "arp spoof", 0.95),
    MappingRule("mitm-2", ["T1557"], "keyword", "man-in-the-middle", 0.90),
    MappingRule("mitm-3", ["T1557"], "keyword", "mitm", 0.85),

    # ── Category-based rules ───────────────────────────────────────────────────
    MappingRule("cat-1", ["T1595.002", "T1190"], "category", "vuln", 0.60),
    MappingRule("cat-2", ["T1046", "T1590"], "category", "recon", 0.55),
    MappingRule("cat-3", ["T1190", "T1059"], "category", "exploit", 0.65),
    MappingRule("cat-4", ["T1021", "T1210"], "category", "post", 0.60),
    MappingRule("cat-5", ["T1071", "T1572"], "category", "forensics", 0.50),
    MappingRule("cat-6", ["T1595", "T1046"], "category", "anomaly-detection", 0.50),

    # ── Source-based rules ─────────────────────────────────────────────────────
    MappingRule("src-1", ["T1046", "T1595.001"], "source", "nmap", 0.65),
    MappingRule("src-2", ["T1595.002"], "source", "nuclei", 0.70),
    MappingRule("src-3", ["T1083"], "source", "feroxbuster", 0.70),
    MappingRule("src-4", ["T1190"], "source", "sqlmap", 0.85),
    MappingRule("src-5", ["T1087.002"], "source", "bloodhound", 0.80),
    MappingRule("src-6", ["T1087.002"], "source", "crackmapexec", 0.75),
    MappingRule("src-7", ["T1590.002"], "source", "subfinder", 0.70),

    # ── Miscellaneous ──────────────────────────────────────────────────────────
    MappingRule("misc-1", ["T1539"], "keyword", "cookie", 0.50),
    MappingRule("misc-2", ["T1190"], "keyword", "cve-", 0.70),
    MappingRule("misc-3", ["T1562"], "keyword", "waf bypass", 0.80),
    MappingRule("misc-4", ["T1027"], "keyword", "obfuscat", 0.75),
    MappingRule("misc-5", ["T1491"], "keyword", "defacement", 0.85),
    MappingRule("misc-6", ["T1596.003"], "keyword", "certificate transparency", 0.80),
    MappingRule("misc-7", ["T1593"], "keyword", "wayback", 0.70),
]


# ── Mapper ────────────────────────────────────────────────────────────────────

@dataclass
class TechniqueMapping:
    """Result of mapping a finding to ATT&CK techniques."""
    finding_title: str
    finding_severity: str
    techniques: List[Dict[str, Any]]
    tactics_covered: List[str]
    confidence: float
    kill_chain_phase: int  # 1-14 based on tactic order
    rules_matched: List[str]


class MitreAttackMapper:
    """Maps security findings to MITRE ATT&CK techniques."""

    def __init__(self) -> None:
        self._mappings: List[TechniqueMapping] = []
        self._coverage: Dict[str, Set[str]] = defaultdict(set)  # tactic_id → set of technique_ids

    def map_finding(self, finding: Dict[str, Any]) -> TechniqueMapping:
        """Map a single finding to ATT&CK techniques."""
        title = str(finding.get("title", "")).lower()
        description = str(finding.get("description", "")).lower()
        category = str(finding.get("category", "")).lower()
        source = str(finding.get("source", "")).lower()
        severity = str(finding.get("severity", "info")).lower()

        # Combined text for keyword matching
        combined = f"{title} {description} {category} {source}"

        matched_techniques: Dict[str, float] = {}  # technique_id → max confidence
        matched_rules: List[str] = []

        for rule in MAPPING_RULES:
            match = False
            if rule.match_type == "keyword":
                match = rule.match_value in combined
            elif rule.match_type == "category":
                match = rule.match_value == category
            elif rule.match_type == "source":
                match = rule.match_value == source
            elif rule.match_type == "regex":
                match = bool(re.search(rule.match_value, combined))

            if match:
                matched_rules.append(rule.rule_id)
                for tech_id in rule.techniques:
                    if tech_id in TECHNIQUES:
                        current = matched_techniques.get(tech_id, 0)
                        matched_techniques[tech_id] = max(current, rule.confidence)

        # Build technique details
        technique_details = []
        for tech_id, confidence in sorted(matched_techniques.items(), key=lambda x: -x[1]):
            tech = TECHNIQUES[tech_id]
            technique_details.append({
                "technique_id": tech_id,
                "name": tech.name,
                "tactics": tech.tactics,
                "tactic_ids": tech.tactic_ids,
                "confidence": confidence,
                "url": tech.url,
                "detection": tech.detection,
            })
            # Update coverage
            for tactic_id in tech.tactic_ids:
                self._coverage[tactic_id].add(tech_id)

        # Determine primary kill chain phase
        kill_chain_phase = 1
        tactics_covered: List[str] = []
        for tech in technique_details[:3]:  # type: ignore[assignment]
            for tactic_id in tech.get("tactic_ids", []):  # type: ignore[attr-defined]
                if tactic_id in TACTICS:
                    tactics_covered.append(str(TACTICS[tactic_id]["name"]))
                    kill_chain_phase = max(kill_chain_phase, int(TACTICS[tactic_id]["order"]))

        overall_confidence: float = max(  # type: ignore[type-var]
            (float(t.get("confidence", 0)) for t in technique_details), default=0.0  # type: ignore[arg-type, attr-defined]
        )

        mapping = TechniqueMapping(
            finding_title=str(finding.get("title", "")),
            finding_severity=severity,
            techniques=technique_details,
            tactics_covered=list(set(tactics_covered)),
            confidence=overall_confidence,
            kill_chain_phase=kill_chain_phase,
            rules_matched=matched_rules,
        )
        self._mappings.append(mapping)
        return mapping

    def map_findings(self, findings: List[Dict[str, Any]]) -> List[TechniqueMapping]:
        """Map multiple findings to ATT&CK techniques."""
        return [self.map_finding(f) for f in findings]

    def get_kill_chain_coverage(self) -> Dict[str, Any]:
        """Get a kill chain coverage report showing which tactics are covered."""
        coverage = {}
        for tactic_id, info in sorted(TACTICS.items(), key=lambda x: int(x[1]["order"])):
            techniques_hit = self._coverage.get(tactic_id, set())
            coverage[tactic_id] = {
                "name": info["name"],
                "order": info["order"],
                "techniques_observed": len(techniques_hit),
                "technique_ids": sorted(techniques_hit),
            }
        return coverage

    def get_coverage_gaps(self) -> List[Dict[str, Any]]:
        """Identify tactics with no observed techniques (kill chain gaps)."""
        gaps: List[Dict[str, Any]] = []
        for tactic_id, info in sorted(TACTICS.items(), key=lambda x: int(x[1]["order"])):
            if tactic_id not in self._coverage or not self._coverage[tactic_id]:
                gaps.append({
                    "tactic_id": tactic_id,
                    "tactic_name": info["name"],
                    "phase": info["order"],
                })
        return gaps

    def get_technique_frequency(self) -> List[Dict[str, Any]]:
        """Get most frequently mapped techniques across all findings."""
        tech_counter: Counter = Counter()
        for mapping in self._mappings:
            for tech in mapping.techniques:
                tech_counter[tech["technique_id"]] += 1

        return [
            {
                "technique_id": tid,
                "name": TECHNIQUES[tid].name if tid in TECHNIQUES else "Unknown",
                "count": count,
                "tactics": TECHNIQUES[tid].tactics if tid in TECHNIQUES else [],
            }
            for tid, count in tech_counter.most_common(20)
        ]

    def generate_attack_narrative(self) -> str:
        """Generate a human-readable attack narrative based on mapped techniques."""
        if not self._mappings:
            return "No findings mapped to ATT&CK techniques."

        # Group by kill chain phase
        phases: Dict[int, List[TechniqueMapping]] = defaultdict(list)
        for mapping in self._mappings:
            phases[mapping.kill_chain_phase].append(mapping)

        narrative_parts = []
        narrative_parts.append("# Attack Narrative (MITRE ATT&CK)\n")

        for phase_num in sorted(phases.keys()):
            mappings = phases[phase_num]
            # Find tactic name for this phase
            tactic_name = "Unknown"
            for info in TACTICS.values():
                if info["order"] == phase_num:
                    tactic_name = str(info["name"])
                    break

            narrative_parts.append(f"\n## Phase {phase_num}: {tactic_name}\n")

            for mapping in mappings[:5]:
                techniques_str = ", ".join(
                    f"{t['technique_id']} ({t['name']})"
                    for t in mapping.techniques[:3]
                )
                narrative_parts.append(
                    f"- **{mapping.finding_title}** [{mapping.finding_severity.upper()}]\n"
                    f"  Techniques: {techniques_str}\n"
                )

        return "\n".join(narrative_parts)

    def summary(self) -> Dict[str, Any]:
        """Get overall mapping summary."""
        total_findings = len(self._mappings)
        mapped = sum(1 for m in self._mappings if m.techniques)
        unmapped = total_findings - mapped

        all_techniques: Set[str] = set()
        all_tactics: Set[str] = set()
        for mapping in self._mappings:
            for tech in mapping.techniques:
                all_techniques.add(tech["technique_id"])
                all_tactics.update(tech.get("tactic_ids", []))

        return {
            "total_findings": total_findings,
            "mapped_findings": mapped,
            "unmapped_findings": unmapped,
            "coverage_percentage": round((mapped / total_findings * 100) if total_findings else 0, 1),
            "unique_techniques": len(all_techniques),
            "tactics_covered": len(all_tactics),
            "total_tactics": len(TACTICS),
            "kill_chain_coverage_pct": round(len(all_tactics) / len(TACTICS) * 100, 1),
        }

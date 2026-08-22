"""Service identification data and helpers.

Three responsibilities:

    * map well-known ports to service names,
    * refine a service guess from a grabbed banner,
    * surface an advisory note for services that are commonly misconfigured.

The advisory notes are review prompts, not vulnerability assertions. A port
being open is not a finding on its own; it is a starting point for analysis.
"""

from __future__ import annotations

import re
from re import Pattern

PORT_SERVICES: dict[int, str] = {
    7: "echo", 19: "chargen", 20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 43: "whois", 53: "dns",
    67: "dhcp", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmp-trap", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 500: "ike", 512: "rexec", 513: "rlogin",
    514: "syslog", 515: "lpd", 587: "smtp-submission", 631: "ipp",
    636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 3000: "http-dev",
    3128: "squid", 3306: "mysql", 3389: "rdp", 3690: "svn", 4444: "krb524",
    5000: "upnp", 5060: "sip", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
    6443: "kubernetes-api", 7001: "weblogic", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 50070: "hadoop",
}

ADVISORY_NOTES: dict[int, str] = {
    21: "FTP frequently permits anonymous or cleartext authentication.",
    23: "Telnet transmits credentials in cleartext.",
    69: "TFTP provides no authentication.",
    79: "Finger can disclose local user information.",
    111: "rpcbind is a common reconnaissance and amplification vector.",
    135: "MSRPC exposure is a frequent lateral-movement path.",
    139: "Legacy NetBIOS exposure; disable where possible.",
    445: "SMB has a history of critical remote vulnerabilities.",
    512: "rexec is an insecure legacy remote-execution service.",
    513: "rlogin is an insecure legacy trust-based service.",
    1433: "Database service; should not be internet-facing without controls.",
    2375: "Unauthenticated Docker API can lead to host compromise.",
    3306: "Database service; verify it is not externally reachable.",
    3389: "RDP is a common brute-force and ransomware entry point.",
    5432: "Database service; verify network exposure and authentication.",
    5900: "VNC is often unauthenticated or weakly authenticated.",
    6379: "Redis defaults to no authentication.",
    9200: "Elasticsearch exposes indexed data without access controls.",
    10000: "Webmin has had multiple critical remote-code-execution issues.",
    11211: "Memcached is widely abused for reflection/amplification.",
    27017: "MongoDB historically shipped without default authentication.",
    2049: "NFS exports may expose the filesystem to the network.",
    6443: "Kubernetes API exposure can lead to cluster compromise.",
}

_BANNER_SIGNATURES: tuple[tuple[Pattern[bytes], str], ...] = (
    (re.compile(rb"SSH-\d", re.IGNORECASE), "ssh"),
    (re.compile(rb"HTTP/\d", re.IGNORECASE), "http"),
    (re.compile(rb"220[- ].*FTP", re.IGNORECASE), "ftp"),
    (re.compile(rb"220[- ].*SMTP", re.IGNORECASE), "smtp"),
    (re.compile(rb"\+OK", re.IGNORECASE), "pop3"),
    (re.compile(rb"^\* OK", re.IGNORECASE), "imap"),
    (re.compile(rb"^RFB \d", re.IGNORECASE), "vnc"),
    (re.compile(rb"mysql", re.IGNORECASE), "mysql"),
)

# Curated common-service ports for the --top-ports convenience flag.
TOP_PORTS: tuple[int, ...] = tuple(sorted({
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 2181,
    2375, 3000, 3128, 3306, 3389, 5000, 5432, 5601, 5672, 5900, 5985, 6379,
    6443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9092, 9200, 9300, 10000,
    11211, 15672, 27017, 50070,
}))

UNKNOWN = "unknown"


def name_for_port(port: int) -> str:
    """Return the well-known service name for *port*, or ``"unknown"``."""
    return PORT_SERVICES.get(port, UNKNOWN)


def advisory_for_port(port: int) -> str | None:
    """Return a review advisory for *port*, if one is defined."""
    return ADVISORY_NOTES.get(port)


def refine_from_banner(banner: bytes, fallback: str) -> str:
    """Improve a port-based service guess using signatures in *banner*."""
    if not banner:
        return fallback
    for pattern, name in _BANNER_SIGNATURES:
        if pattern.search(banner):
            return name
    return fallback

"""
agents/network/network_agent.py — Network Scanning Agent

Performs port scanning, service fingerprinting, banner grabbing,
and known-service vulnerability checks.
"""
from __future__ import annotations

import asyncio
import socket
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from rich.console import Console

from agents.base import BaseAgent
from core.models import AgentType, Finding, FindingCategory, Scan, Severity

console = Console()

# ── Service Fingerprints ───────────────────────────────────────────────

SERVICE_MAP: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "smb",
    1433: "mssql", 1521: "oracle", 2049: "nfs",
    3000: "http-dev", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

# ── Dangerous Open Ports ───────────────────────────────────────────────

DANGEROUS_SERVICES: Dict[str, Tuple[str, Severity]] = {
    "telnet":        ("Telnet transmits data in cleartext.", Severity.HIGH),
    "ftp":           ("FTP transmits credentials in cleartext.", Severity.HIGH),
    "rpcbind":       ("RPC portmapper exposed — potential pivot point.", Severity.MEDIUM),
    "netbios-ssn":   ("NetBIOS session service exposed.", Severity.MEDIUM),
    "smb":           ("SMB exposed — check for EternalBlue and related CVEs.", Severity.HIGH),
    "rdp":           ("RDP exposed — brute-force and BlueKeep risk.", Severity.HIGH),
    "vnc":           ("VNC exposed — assess authentication strength.", Severity.HIGH),
    "redis":         ("Redis exposed — often unauthenticated.", Severity.CRITICAL),
    "memcached":     ("Memcached exposed — DDoS amplification and data leak risk.", Severity.HIGH),
    "mongodb":       ("MongoDB exposed — often unauthenticated.", Severity.CRITICAL),
    "elasticsearch": ("Elasticsearch exposed — no auth by default.", Severity.CRITICAL),
    "oracle":        ("Oracle DB exposed — assess authentication.", Severity.HIGH),
    "mssql":         ("MS SQL Server exposed — assess authentication.", Severity.HIGH),
    "mysql":         ("MySQL exposed — assess authentication.", Severity.HIGH),
    "postgresql":    ("PostgreSQL exposed — assess authentication.", Severity.HIGH),
    "nfs":           ("NFS exposed — may allow unauthenticated file access.", Severity.HIGH),
    "ldap":          ("LDAP exposed — may allow anonymous bind.", Severity.MEDIUM),
    "http-dev":      ("Development HTTP server exposed publicly.", Severity.MEDIUM),
    "dns":           ("DNS exposed — check for zone transfer vulnerability.", Severity.LOW),
}

# ── Banner Probes ─────────────────────────────────────────────────────

BANNER_PROBES: Dict[int, bytes] = {
    80:    b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    443:   b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    21:    b"",   # FTP sends banner on connect
    22:    b"",   # SSH sends banner on connect
    25:    b"EHLO test\r\n",
    110:   b"",   # POP3 banner on connect
    143:   b"",   # IMAP banner on connect
    6379:  b"*1\r\n$4\r\nPING\r\n",  # Redis PING
    27017: b"",   # MongoDB sends response on connect
}


class NetworkAgent(BaseAgent):
    """Network scanning agent for port discovery and service analysis."""

    agent_type = AgentType.NETWORK

    async def execute(self, scan_id: str, target: str, **kwargs) -> None:
        """
        target: hostname or IP address.
        kwargs:
            ports: Optional[List[int]] — custom port list
        """
        host = target.strip()
        # Strip protocol if present
        host = re.sub(r'^https?://', '', host).split('/')[0].split(':')[0]

        ports = kwargs.get("ports") or self.config.network.common_ports

        self.log_info(f"Scanning {host} — {len(ports)} port(s)")

        # Resolve hostname
        try:
            ip = socket.gethostbyname(host)
            if ip != host:
                self.log(f"  Resolved {host} → {ip}")
        except socket.gaierror:
            self.log_error(f"Cannot resolve host: {host}")
            return

        # Port scan
        open_ports = await self._scan_ports(host, ports)
        self.log_info(f"Open ports: {open_ports if open_ports else 'none found'}")

        for port in open_ports:
            await self._analyze_port(scan_id, host, port)

        # Try nmap if on Linux (non-blocking)
        await self._try_nmap(scan_id, host, open_ports)

    # ── Port Scanner ──────────────────────────────────────────────────

    async def _scan_ports(self, host: str, ports: List[int]) -> List[int]:
        """Async TCP connect scan."""
        timeout = self.config.network.port_scan_timeout
        sem = asyncio.Semaphore(100)

        async def probe(port: int) -> Optional[int]:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=timeout
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return port
                except Exception:
                    return None

        results = await asyncio.gather(*[probe(p) for p in ports])
        return sorted(p for p in results if p is not None)

    # ── Port Analysis ─────────────────────────────────────────────────

    async def _analyze_port(self, scan_id: str, host: str, port: int) -> None:
        service = SERVICE_MAP.get(port, f"unknown-{port}")
        banner = ""

        # Banner grab
        if self.config.network.banner_grabbing:
            banner = await self._grab_banner(host, port)

        # Log the open port
        self.log(f"  [green]●[/green] {port}/tcp  {service}  {banner[:60]}")

        # Emit open port finding
        await self.emit_finding(Finding(
            scan_id=scan_id,
            agent=AgentType.NETWORK,
            category=FindingCategory.OPEN_PORT,
            severity=Severity.INFO,
            title=f"Open Port: {port}/{service}",
            description=f"Port {port} ({service}) is open on {host}.\nBanner: {banner}",
            url=f"{host}:{port}",
            raw_output=banner,
            confidence=0.99,
        ))

        # Dangerous service check
        if service in DANGEROUS_SERVICES:
            desc, sev = DANGEROUS_SERVICES[service]
            await self.emit_finding(Finding(
                scan_id=scan_id,
                agent=AgentType.NETWORK,
                category=FindingCategory.EXPOSED_SERVICE,
                severity=sev,
                title=f"Dangerous Service Exposed: {service.upper()} on port {port}",
                description=f"{desc}\nBanner: {banner}",
                url=f"{host}:{port}",
                remediation=f"Firewall port {port} or ensure {service} requires authentication.",
                confidence=0.9,
            ))

        # Version disclosure from banner
        await self._check_banner_vulns(scan_id, host, port, service, banner)

    async def _grab_banner(self, host: str, port: int) -> str:
        """Attempt to grab service banner."""
        timeout = self.config.network.banner_grab_timeout
        probe = BANNER_PROBES.get(port, b"\r\n")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            if probe:
                writer.write(probe)
                await writer.drain()

            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return banner_bytes.decode(errors="replace").strip()
        except Exception:
            return ""

    async def _check_banner_vulns(
        self, scan_id: str, host: str, port: int, service: str, banner: str
    ) -> None:
        """Detect version from banner and flag known vulnerable versions."""
        if not banner:
            return

        BANNER_CHECKS = [
            # OpenSSH version check
            (re.compile(r'OpenSSH[_\s]([\d\.]+)', re.I),
             "ssh", "OpenSSH"),
            # Apache version
            (re.compile(r'Apache/([\d\.]+)', re.I),
             "http", "Apache HTTPD"),
            # nginx version
            (re.compile(r'nginx/([\d\.]+)', re.I),
             "http", "nginx"),
            # vsftpd
            (re.compile(r'vsftpd\s+([\d\.]+)', re.I),
             "ftp", "vsftpd"),
            # Redis version
            (re.compile(r'redis_version:([\d\.]+)', re.I),
             "redis", "Redis"),
            # MongoDB version
            (re.compile(r'"version"\s*:\s*"([\d\.]+)"', re.I),
             "mongodb", "MongoDB"),
        ]

        for pattern, svc, software in BANNER_CHECKS:
            m = pattern.search(banner)
            if m:
                version = m.group(1)
                await self.emit_finding(Finding(
                    scan_id=scan_id,
                    agent=AgentType.NETWORK,
                    category=FindingCategory.SENSITIVE_EXPOSURE,
                    severity=Severity.INFO,
                    title=f"Version Disclosure: {software} {version} on port {port}",
                    description=(
                        f"{software} version {version} identified from banner.\n"
                        "Check CVE databases for known vulnerabilities in this version."
                    ),
                    url=f"{host}:{port}",
                    raw_output=banner,
                    confidence=0.95,
                ))

    async def _try_nmap(self, scan_id: str, host: str, open_ports: List[int]) -> None:
        """Try to run nmap for deeper service/OS detection (Linux only)."""
        if not open_ports:
            return
        port_str = ",".join(str(p) for p in open_ports)
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sV", "-O", "--open", "-p", port_str,
                "-oX", "-", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            nmap_output = stdout.decode(errors="replace")

            if "nmap scan report" in nmap_output.lower():
                self.log_info("nmap deep scan complete.")
                # Could parse XML for more detailed findings — future enhancement
        except FileNotFoundError:
            self.log("[dim]  nmap not available (install on Linux for deeper analysis)[/dim]")
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

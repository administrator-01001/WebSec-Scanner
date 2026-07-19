import asyncio
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding
from webscanner.config import COMMON_PORTS


PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "SonarQube",
    9090: "WebLogic", 27017: "MongoDB",
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9090, 27017]


@plugin("port_scan", "Scan common ports on target", "recon")
class PortScanPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        target_ip = target.ip or target.domain
        open_ports = []

        async def scan_port(port):
            try:
                conn = asyncio.open_connection(target_ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=3)
                writer.close()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        sem = asyncio.Semaphore(50)

        async def bounded_scan(port):
            async with sem:
                return await scan_port(port)

        tasks = [bounded_scan(p) for p in COMMON_PORTS]
        results = await asyncio.gather(*tasks)

        for port in results:
            if port:
                open_ports.append(port)
                service = PORT_NAMES.get(port, "Unknown")
                sev = "high" if port in (21, 23, 135, 139, 445, 3389, 6379, 27017) else "info"
                findings.append(Finding(
                    type="open_port",
                    name=f"Open Port: {port}/{service}",
                    severity=sev,
                    description=f"Port {port} ({service}) is open",
                    evidence=f"{target_ip}:{port}",
                    recommendation=f"Close port {port} if not needed, or restrict access with firewall" if sev == "high" else "",
                    module="port_scan",
                    url=target.url,
                ))

        target.open_ports = open_ports

        return findings

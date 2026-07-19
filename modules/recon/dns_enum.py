import socket
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding


@plugin("dns_enum", "Enumerate DNS records for target domain", "recon")
class DNSEnumPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        domain = target.domain

        try:
            ip = socket.gethostbyname(domain)
            findings.append(Finding(
                type="dns_info",
                name="DNS A Record",
                severity="info",
                description=f"{domain} resolves to {ip}",
                evidence=ip,
                module="dns_enum",
                url=target.url,
            ))
            target.ip = ip
        except socket.gaierror:
            findings.append(Finding(
                type="dns_error",
                name="DNS Resolution Failed",
                severity="high",
                description=f"Cannot resolve {domain}",
                module="dns_enum",
                url=target.url,
            ))
            return findings

        record_types = ["MX", "NS", "TXT", "SOA"]
        for rtype in record_types:
            try:
                import asyncio
                proc = await asyncio.create_subprocess_exec(
                    "nslookup", "-type=" + rtype, domain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                if stdout:
                    output = stdout.decode("utf-8", errors="ignore")
                    lines = [l.strip() for l in output.splitlines() if l.strip() and domain in l.lower()]
                    if lines:
                        findings.append(Finding(
                            type="dns_record",
                            name=f"DNS {rtype} Record",
                            severity="info",
                            description=f"Found {len(lines)} {rtype} record(s)",
                            evidence="\n".join(lines[:5])[:500],
                            module="dns_enum",
                            url=target.url,
                        ))
            except (FileNotFoundError, asyncio.TimeoutError):
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, rtype)
                    if answers:
                        findings.append(Finding(
                            type="dns_record",
                            name=f"DNS {rtype} Record",
                            severity="info",
                            description=f"Found {len(answers)} {rtype} record(s)",
                            evidence="\n".join(str(a) for a in answers[:5])[:500],
                            module="dns_enum",
                            url=target.url,
                        ))
                except ImportError:
                    pass

        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=ANY", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            if stdout:
                output = stdout.decode("utf-8", errors="ignore")
                lines = [l.strip() for l in output.splitlines() if l.strip() and "canonical name" in l.lower()]
                for line in lines:
                    findings.append(Finding(
                        type="dns_cname",
                        name="DNS CNAME Record",
                        severity="info",
                        description=line[:200],
                        module="dns_enum",
                        url=target.url,
                    ))
        except (FileNotFoundError, asyncio.TimeoutError):
            pass

        try:
            rev_ip = socket.gethostbyaddr(ip)
            findings.append(Finding(
                type="dns_ptr",
                name="DNS Reverse Lookup (PTR)",
                severity="info",
                description=f"Reverse DNS: {rev_ip[0]}",
                module="dns_enum",
                url=target.url,
            ))
        except (socket.herror, socket.gaierror):
            pass

        return findings

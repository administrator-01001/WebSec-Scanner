import ssl
import socket
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding


@plugin("ssl_tls", "Check SSL/TLS certificate and configuration", "recon")
class SSLTLSPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        hostname = urlparse(target.url).hostname or target.domain
        if not hostname:
            return findings

        result = await asyncio.to_thread(self._check_ssl_sync, hostname, target.url)
        findings.extend(result)

        return findings

    def _check_ssl_sync(self, hostname: str, url: str) -> list[Finding]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        not_after = cert.get("notAfter", "")
                        not_before = cert.get("notBefore", "")

                        findings.append(Finding(
                            type="ssl_info",
                            name="SSL Certificate Info",
                            severity="info",
                            description=f"Issued to: {subject.get('commonName', 'N/A')}, Issuer: {issuer.get('commonName', 'N/A')}",
                            evidence=f"Valid from {not_before} to {not_after}",
                            module="ssl_tls",
                            url=url,
                        ))

                        if not_after:
                            try:
                                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_left = (expiry - datetime.utcnow()).days
                                if days_left < 0:
                                    findings.append(Finding(
                                        type="expired_cert",
                                        name="SSL Certificate Expired",
                                        severity="critical",
                                        description=f"SSL certificate expired {abs(days_left)} days ago",
                                        recommendation="Renew the SSL certificate immediately",
                                        module="ssl_tls",
                                        url=url,
                                    ))
                                elif days_left < 30:
                                    findings.append(Finding(
                                        type="expiring_cert",
                                        name="SSL Certificate Expiring Soon",
                                        severity="high",
                                        description=f"SSL certificate expires in {days_left} days",
                                        recommendation="Renew the SSL certificate soon",
                                        module="ssl_tls",
                                        url=url,
                                    ))
                            except ValueError:
                                pass

                    version = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        findings.append(Finding(
                            type="ssl_cipher",
                            name="SSL/TLS Version & Cipher",
                            severity="info",
                            description=f"Protocol: {version}, Cipher: {cipher[0]}",
                            module="ssl_tls",
                            url=url,
                        ))

                    if version in ("TLSv1", "TLSv1.1"):
                        findings.append(Finding(
                            type="weak_tls",
                            name=f"Weak TLS Version ({version})",
                            severity="high",
                            description=f"Server supports outdated {version} protocol",
                            recommendation="Disable TLS 1.0 and 1.1, enable TLS 1.2 and 1.3",
                            module="ssl_tls",
                            url=url,
                        ))

        except ssl.CertificateError as e:
            findings.append(Finding(
                type="ssl_hostname_mismatch",
                name="SSL Hostname Mismatch",
                severity="high",
                description=f"SSL certificate not valid for {hostname}: {str(e)[:200]}",
                module="ssl_tls",
                url=url,
            ))
        except ssl.SSLError as e:
            findings.append(Finding(
                type="ssl_error",
                name="SSL Protocol Error",
                severity="high",
                description=str(e)[:200],
                module="ssl_tls",
                url=url,
            ))
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            findings.append(Finding(
                type="ssl_connection_error",
                name="SSL Connection Error",
                severity="info",
                description=f"Could not connect: {str(e)[:200]}",
                module="ssl_tls",
                url=url,
            ))

        return findings

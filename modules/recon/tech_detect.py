import re
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding


TECH_PATTERNS = [
    {"name": "Laravel", "patterns": [r'laravel', r'_laravel', r'XSRF-TOKEN', r'__cfduid'], "type": "Framework"},
    {"name": "Symfony", "patterns": [r'symfony', r'_sf2_attributes'], "type": "Framework"},
    {"name": "Django", "patterns": [r'django', r'csrftoken', r'__django'], "type": "Framework"},
    {"name": "Rails", "patterns": [r'rails', r'_rails', r'rails_admin'], "type": "Framework"},
    {"name": "Express", "patterns": [r'express', r'X-Powered-By: Express'], "type": "Framework"},
    {"name": "Spring", "patterns": [r'spring', r'X-Application-Context'], "type": "Framework"},
    {"name": "ASP.NET", "patterns": [r'asp\.net', r'x-aspnet', r'__viewstate', r'__requestverificationtoken'], "type": "Framework"},
    {"name": "WordPress", "patterns": [r'wp-content', r'wp-includes', r'wp-json', r'wordpress'], "type": "CMS"},
    {"name": "Joomla", "patterns": [r'joomla', r'com_content', r'com_users'], "type": "CMS"},
    {"name": "Drupal", "patterns": [r'drupal', r'sites/all', r'core/modules'], "type": "CMS"},
    {"name": "Magento", "patterns": [r'magento', r'skin/frontend', r'x-magento'], "type": "CMS"},
    {"name": "jQuery", "patterns": [r'jquery'], "type": "Library"},
    {"name": "React", "patterns": [r'react\.js', r'react-dom', r'__REACT_DEVTOOLS'], "type": "Library"},
    {"name": "Vue.js", "patterns": [r'vue\.js', r'vue\.min\.js', r'__vue__'], "type": "Library"},
    {"name": "Angular", "patterns": [r'angular\.js', r'ng-app', r'ng-version'], "type": "Library"},
    {"name": "Bootstrap", "patterns": [r'bootstrap\.', r'bs-'], "type": "Library"},
    {"name": "Tailwind CSS", "patterns": [r'tailwind'], "type": "Library"},
    {"name": "Alpine.js", "patterns": [r'alpinejs', r'x-data', r'x-init'], "type": "Library"},
    {"name": "Nginx", "patterns": [r'nginx', r'Server: nginx'], "type": "Server"},
    {"name": "Apache", "patterns": [r'apache', r'Server: Apache'], "type": "Server"},
    {"name": "IIS", "patterns": [r'iis', r'Server: Microsoft-IIS'], "type": "Server"},
    {"name": "Cloudflare", "patterns": [r'cloudflare', r'__cfduid', r'cf-ray'], "type": "CDN"},
    {"name": "CloudFront", "patterns": [r'cloudfront', r'x-amz-cf'], "type": "CDN"},
    {"name": "Fastly", "patterns": [r'fastly'], "type": "CDN"},
    {"name": "Redis", "patterns": [r'redis'], "type": "Cache"},
    {"name": "Varnish", "patterns": [r'varnish', r'X-Varnish'], "type": "Cache"},
    {"name": "MySQL", "patterns": [r'mysql'], "type": "Database"},
    {"name": "PostgreSQL", "patterns": [r'postgres', r'pgsql'], "type": "Database"},
    {"name": "MongoDB", "patterns": [r'mongodb'], "type": "Database"},
    {"name": "GraphQL", "patterns": [r'graphql'], "type": "API"},
    {"name": "Swagger", "patterns": [r'swagger', r'openapi'], "type": "API"},
    {"name": "PHP", "patterns": [r'\.php', r'x-powered-by: php', r'php/'], "type": "Language"},
    {"name": "Python", "patterns": [r'\.py', r'python', r'flask'], "type": "Language"},
    {"name": "Ruby", "patterns": [r'\.rb', r'ruby'], "type": "Language"},
    {"name": "Java", "patterns": [r'\.jsp', r'\.do', r'java', r'servlet'], "type": "Language"},
    {"name": "Node.js", "patterns": [r'node', r'\.node'], "type": "Language"},
    {"name": "Go", "patterns": [r'\.go', r'golang'], "type": "Language"},
    {"name": "Docker", "patterns": [r'docker'], "type": "Platform"},
    {"name": "Kubernetes", "patterns": [r'kubernetes', r'k8s'], "type": "Platform"},
    {"name": "Stripe", "patterns": [r'stripe\.com', r'pk_live', r'sk_live'], "type": "Payment"},
    {"name": "PayPal", "patterns": [r'paypal', r'paypalobjects'], "type": "Payment"},
    {"name": "Google Analytics", "patterns": [r'google-analytics\.com', r'gtag'], "type": "Analytics"},
    {"name": "Hotjar", "patterns": [r'hotjar'], "type": "Analytics"},
    {"name": "Livewire", "patterns": [r'livewire', r'wire:'], "type": "Library"},
    {"name": "Alpine.js", "patterns": [r'alpinejs', r'x-data', r'x-init', r'x-on'], "type": "Library"},
    {"name": "Filament", "patterns": [r'filament'], "type": "Admin"},
    {"name": "Nova", "patterns": [r'nova'], "type": "Admin"},
]


@plugin("tech_detect", "Detect technologies used by the target", "recon")
class TechDetectPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        detected = {}

        try:
            resp = await http_client.get(target.url)
            body = resp.text
            headers_text = str(resp.headers)

            combined = body + "\n" + headers_text

            for tech in TECH_PATTERNS:
                for pattern in tech["patterns"]:
                    if re.search(pattern, combined, re.IGNORECASE):
                        if tech["name"] not in detected:
                            detected[tech["name"]] = tech["type"]
                            findings.append(Finding(
                                type="tech_detected",
                                name=f"{tech['name']} ({tech['type']})",
                                severity="info",
                                description=f"Detected {tech['type']}: {tech['name']}",
                                module="tech_detect",
                                url=target.url,
                            ))
                        break

            target.tech_stack = detected

            if "PHP" in detected:
                version_match = re.search(r'PHP/([\d.]+)', combined, re.IGNORECASE)
                if version_match:
                    findings.append(Finding(
                        type="version_detected",
                        name=f"PHP Version: {version_match.group(1)}",
                        severity="info",
                        description=f"PHP version {version_match.group(1)} detected",
                        module="tech_detect",
                        url=target.url,
                    ))

            if "Nginx" in detected:
                ver = re.search(r'nginx/([\d.]+)', combined, re.IGNORECASE)
                if ver:
                    findings.append(Finding(
                        type="version_detected",
                        name=f"Nginx {ver.group(1)}",
                        severity="info",
                        description=f"Nginx version {ver.group(1)} detected",
                        module="tech_detect",
                        url=target.url,
                    ))

        except Exception:
            findings.append(Finding(
                type="error",
                name="Tech Detection Failed",
                severity="info",
                description=f"Could not detect technologies for {target.url}",
                module="tech_detect",
                url=target.url,
            ))

        return findings

import re
from urllib.parse import urlparse, urljoin
from typing import Optional


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def normalize_url(url: str, base: str = "") -> str:
    if not url.startswith(("http://", "https://")):
        if base:
            return urljoin(base, url)
        url = "https://" + url
    return url.rstrip("/")


def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r"^(https?://)"
        r"([\w.-]+)"
        r"(:\d+)?"
        r"(/[\w\-._~:/?#\[\]@!$&'()*+,;=]*)?"
        r"$"
    )
    return bool(pattern.match(url))


def extract_forms(html: str) -> list[dict]:
    forms = []
    pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    for form_match in pattern.finditer(html):
        form_html = form_match.group(0)
        action = re.search(r'action=["\'](.*?)["\']', form_html, re.IGNORECASE)
        method = re.search(r'method=["\'](.*?)["\']', form_html, re.IGNORECASE)
        inputs = []
        for inp in re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE):
            inp_name = re.search(r'name=["\'](.*?)["\']', inp.group(0), re.IGNORECASE)
            inp_type = re.search(r'type=["\'](.*?)["\']', inp.group(0), re.IGNORECASE)
            inputs.append({
                "name": inp_name.group(1) if inp_name else "",
                "type": inp_type.group(1) if inp_type else "text",
            })
        forms.append({
            "action": action.group(1) if action else "",
            "method": method.group(1).upper() if method else "GET",
            "inputs": inputs,
        })
    return forms


def extract_links(html: str, base_url: str) -> list[str]:
    links = set()
    patterns = [
        r'href=["\'](.*?)["\']',
        r'src=["\'](.*?)["\']',
        r'data-src=["\'](.*?)["\']',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            link = match.group(1)
            if link and not link.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
                if link.startswith(("http://", "https://")):
                    links.add(link.rstrip("/"))
                elif link.startswith("/"):
                    parsed = urlparse(base_url)
                    links.add(f"{parsed.scheme}://{parsed.netloc}{link}".rstrip("/"))
                elif link:
                    links.add(urljoin(base_url, link).rstrip("/"))
    return list(links)


def extract_js_urls(html: str, base_url: str) -> list[str]:
    urls = set()
    for match in re.finditer(r'(?:src|href|data-url|action)=["\']([^"\']+\.(?:js|json|xml|php|aspx|jsp|do|action)[^"\']*)["\']', html, re.IGNORECASE):
        url = match.group(1)
        if url.startswith("http"):
            urls.add(url)
        elif url.startswith("/"):
            parsed = urlparse(base_url)
            urls.add(f"{parsed.scheme}://{parsed.netloc}{url}")
        else:
            urls.add(urljoin(base_url, url))
    return list(urls)


def extract_api_endpoints(html: str, base_url: str) -> list[str]:
    endpoints = set()
    patterns = [
        r'["\'](/api/[^"\']*)["\']',
        r'["\'](/v[0-9]+/[^"\']*)["\']',
        r'["\'](/graphql)[^"\']*["\']',
        r'["\'](/swagger[^"\']*)["\']',
        r'["\'](/docs[^"\']*)["\']',
        r'["\'](/rest/[^"\']*)["\']',
        r'["\'](/internal[^"\']*)["\']',
        r'["\'](/admin[^"\']*)["\']',
        r'["\'](/private[^"\']*)["\']',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            endpoint = match.group(1)
            if endpoint.startswith("/"):
                parsed = urlparse(base_url)
                endpoints.add(f"{parsed.scheme}://{parsed.netloc}{endpoint}")
            else:
                endpoints.add(endpoint)
    return list(endpoints)


def truncate(s: str, max_len: int = 200) -> str:
    return s[:max_len] + "..." if len(s) > max_len else s

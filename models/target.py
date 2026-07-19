from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanTarget:
    url: str
    domain: str = ""
    ip: str = ""
    mode: str = "quick"
    ports: list[int] = field(default_factory=list)
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    threads: int = 1
    proxy: Optional[str] = None
    crawl_depth: int = 2
    max_pages: int = 50
    custom_plugins: list[str] = field(default_factory=list)

    def __post_init__(self):
        from urllib.parse import urlparse
        if not self.url.startswith(("http://", "https://")):
            self.url = "https://" + self.url
        parsed = urlparse(self.url)
        self.domain = parsed.hostname or parsed.netloc.split(":")[0] or parsed.path

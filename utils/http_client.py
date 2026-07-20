import time
import random
import httpx
import asyncio
from typing import Optional
from webscanner.config import TIMEOUT, USER_AGENTS, MAX_RETRIES, REQUEST_DELAY


class HttpClient:
    def __init__(self, proxy: Optional[str] = None, cookies: Optional[dict] = None, concurrency: int = 10, custom_headers: dict = None, rate_limit: float = 0):
        self._semaphore = asyncio.Semaphore(concurrency)
        self._custom_headers = custom_headers or {}
        self._rate_limit = rate_limit
        self._last_request_time = 0.0

        client_kwargs = {
            "timeout": TIMEOUT,
            "follow_redirects": True,
            "headers": {"User-Agent": random.choice(USER_AGENTS)},
        }
        if proxy:
            client_kwargs["proxy"] = proxy
        if cookies:
            client_kwargs["cookies"] = cookies
        self.client = httpx.AsyncClient(**client_kwargs)

    async def _throttle(self):
        if self._rate_limit <= 0:
            return
        now = time.monotonic()
        min_interval = 1.0 / self._rate_limit
        elapsed = now - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async with self._semaphore:
            await self._throttle()
            if REQUEST_DELAY > 0:
                await asyncio.sleep(random.uniform(REQUEST_DELAY * 0.5, REQUEST_DELAY * 1.5))

            headers = kwargs.pop("headers", {})
            headers.update(self._custom_headers)
            headers.setdefault("User-Agent", random.choice(USER_AGENTS))

            for attempt in range(MAX_RETRIES):
                try:
                    resp = await self.client.request(method, url, headers=headers, **kwargs)

                    if resp.status_code == 429:
                        retry_after = int(resp.headers.get("retry-after", 5))
                        await asyncio.sleep(min(retry_after, 30))
                        continue
                    if resp.status_code == 403 and attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(2 ** attempt)
                        headers["User-Agent"] = random.choice(USER_AGENTS)
                        continue

                    return resp
                except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
                    if attempt == MAX_RETRIES - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def close(self):
        await self.client.aclose()

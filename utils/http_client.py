import random
import httpx
import asyncio
from typing import Optional
from webscanner.config import TIMEOUT, USER_AGENTS, MAX_RETRIES, REQUEST_DELAY


class HttpClient:
    def __init__(self, proxy: Optional[str] = None, cookies: Optional[dict] = None, concurrency: int = 10):
        self._semaphore = asyncio.Semaphore(concurrency)
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

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async with self._semaphore:
            if REQUEST_DELAY:
                await asyncio.sleep(random.uniform(REQUEST_DELAY * 0.5, REQUEST_DELAY * 1.5))

            headers = kwargs.pop("headers", {})
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
                except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as e:
                    if attempt == MAX_RETRIES - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def close(self):
        await self.client.aclose()

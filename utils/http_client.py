import httpx
import asyncio
from typing import Optional
from webscanner.config import TIMEOUT, USER_AGENT, MAX_RETRIES


class HttpClient:
    def __init__(self, proxy: Optional[str] = None, cookies: Optional[dict] = None):
        client_kwargs = {
            "timeout": TIMEOUT,
            "follow_redirects": True,
            "headers": {"User-Agent": USER_AGENT},
        }
        if proxy:
            client_kwargs["proxy"] = proxy
        if cookies:
            client_kwargs["cookies"] = cookies
        self.client = httpx.AsyncClient(**client_kwargs)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        for attempt in range(MAX_RETRIES):
            try:
                resp = await self.client.request(method, url, **kwargs)
                return resp
            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as e:
                if attempt == MAX_RETRIES - 1:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def close(self):
        await self.client.aclose()

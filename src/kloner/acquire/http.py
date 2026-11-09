"""Fetch discipline (§8.3).

* HTTPS by default; plain HTTP only where a caller allows it (the ``url`` source), labeled
  INSECURE_TRANSPORT.
* Honest User-Agent, per-host rate limit (default 1 request/second), retries with exponential
  backoff and jitter, connect/read timeouts, hard size caps, streaming into the quarantine.
* Redirects are followed manually so every hop can be checked (vendor-domain rule, §7.2).
* Bot protection is never bypassed: a challenge page is reported as BLOCKED.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from kloner.acquire.quarantine import QuarantineError, Sink
from kloner.util.logging import get_logger, log_event, safe_url

RedirectPolicy = Callable[[str], None]  # raises HttpError to refuse a hop
_log = get_logger("http")
_jitter = secrets.SystemRandom()
CHALLENGE_MARKERS = (
    b"cf-chl",
    b"challenge-platform",
    b"captcha",
    b"just a moment...",
    b"attention required!",
    b"ddos-guard",
    b"perimeterx",
    b"px-captcha",
)
RETRY_STATUS = frozenset({500, 502, 503, 504})


class HttpError(Exception):
    def __init__(self, detail: str, *, status: int | None = None, blocked: bool = False, url: str | None = None):
        super().__init__(detail)
        self.detail = detail
        self.status = status
        self.blocked = blocked
        self.url = url


@dataclass
class FetchedDocument:
    url: str
    final_url: str
    status: int
    content_type: str | None
    content: bytes
    chain: list[str] = field(default_factory=list)
    tls_verified: bool = True


@dataclass
class Download:
    url: str
    final_url: str
    status: int
    content_type: str | None
    content_length: int | None
    chain: list[str] = field(default_factory=list)
    tls_verified: bool = True


class RateLimiter:
    def __init__(self, rate_per_host: float) -> None:
        self.interval = 1.0 / rate_per_host if rate_per_host > 0 else 0.0
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                ready = self._next.get(host, 0.0)
                if now >= ready:
                    self._next[host] = now + self.interval
                    return
                delay = ready - now
            time.sleep(delay)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def in_domain(host: str, domain: str) -> bool:
    host, domain = host.lower().rstrip("."), domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def looks_blocked(status: int, headers: httpx.Headers, body_head: bytes) -> bool:
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return True
    if status in (403, 429, 503):
        low = body_head.lower()
        return any(m in low for m in CHALLENGE_MARKERS)
    return False


class Http:
    def __init__(
        self,
        user_agent: str,
        *,
        rate_per_host: float = 1.0,
        connect_timeout: float = 15.0,
        read_timeout: float = 120.0,
        retries: int = 3,
        proxy: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.proxy = proxy
        self.retries = retries
        self.limiter = RateLimiter(rate_per_host)
        timeout = httpx.Timeout(connect=connect_timeout, read=read_timeout, write=read_timeout, pool=connect_timeout)
        self.client = httpx.Client(
            headers={"User-Agent": user_agent, "Accept-Encoding": "identity"},
            timeout=timeout,
            follow_redirects=False,
            proxy=proxy,
            verify=True,
            transport=transport,
        )
        self.requests = 0

    def close(self) -> None:
        self.client.close()

    # -- internals ----------------------------------------------------------------------------

    def _check_scheme(self, url: str, allow_http: bool) -> None:
        scheme = urlsplit(url).scheme.lower()
        if scheme == "https":
            return
        if scheme == "http" and allow_http:
            return
        raise HttpError(f"refusing non-HTTPS URL {url}", url=url)

    def _send(self, method: str, url: str, headers: dict[str, str] | None) -> httpx.Response:
        attempt = 0
        while True:
            self.limiter.wait(host_of(url))
            self.requests += 1
            try:
                req = self.client.build_request(method, url, headers=headers)
                resp = self.client.send(req, stream=True)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError) as e:
                if attempt >= self.retries:
                    log_event(_log, "giving up", event="http.fail", url=safe_url(url), error=type(e).__name__)
                    raise HttpError(f"{type(e).__name__}: {e}", url=url) from e
                log_event(
                    _log, "retry", event="http.retry", url=safe_url(url), error=type(e).__name__, attempt=attempt + 1
                )
                self._backoff(attempt, None)
                attempt += 1
                continue
            if resp.status_code in RETRY_STATUS or resp.status_code == 429:
                head = _peek(resp)
                if looks_blocked(resp.status_code, resp.headers, head):
                    resp.close()
                    log_event(_log, "bot protection", event="http.blocked", url=safe_url(url), status=resp.status_code)
                    raise HttpError(f"bot protection at {host_of(url)}", status=resp.status_code, blocked=True, url=url)
                if attempt >= self.retries:
                    resp.close()
                    log_event(_log, "giving up", event="http.fail", url=safe_url(url), status=resp.status_code)
                    raise HttpError(f"HTTP {resp.status_code}", status=resp.status_code, url=url)
                retry_after = resp.headers.get("retry-after")
                resp.close()
                log_event(
                    _log, "retry", event="http.retry", url=safe_url(url), status=resp.status_code, attempt=attempt + 1
                )
                self._backoff(attempt, retry_after)
                attempt += 1
                continue
            return resp

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay = min(60.0, 2.0**attempt) + _jitter.uniform(0, 0.5)
        if retry_after and retry_after.isdigit():
            delay = min(60.0, max(delay, float(retry_after)))
        time.sleep(delay)

    def _open(
        self,
        url: str,
        *,
        allow_http: bool,
        redirect_policy: RedirectPolicy | None,
        follow: bool,
        headers: dict[str, str] | None,
    ) -> tuple[httpx.Response, list[str]]:
        chain = [url]
        current = url
        for _ in range(10):
            self._check_scheme(current, allow_http)
            if redirect_policy is not None:
                redirect_policy(current)
            resp = self._send("GET", current, headers)
            if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                resp.close()
                if not follow:
                    raise HttpError(f"redirect refused from {current}", status=resp.status_code, url=current)
                current = urljoin(current, resp.headers["location"])
                chain.append(current)
                continue
            if resp.status_code >= 400:
                head = _peek(resp)
                blocked = looks_blocked(resp.status_code, resp.headers, head)
                resp.close()
                log_event(
                    _log,
                    "bot protection" if blocked else "HTTP error",
                    event="http.blocked" if blocked else "http.error",
                    url=safe_url(current),
                    status=resp.status_code,
                )
                raise HttpError(
                    "bot protection" if blocked else f"HTTP {resp.status_code}",
                    status=resp.status_code,
                    blocked=blocked,
                    url=current,
                )
            return resp, chain
        raise HttpError("too many redirects", url=url)

    # -- public -------------------------------------------------------------------------------

    def get_document(
        self,
        url: str,
        max_bytes: int,
        *,
        allow_http: bool = False,
        redirect_policy: RedirectPolicy | None = None,
        follow: bool = True,
        headers: dict[str, str] | None = None,
    ) -> FetchedDocument:
        resp, chain = self._open(
            url, allow_http=allow_http, redirect_policy=redirect_policy, follow=follow, headers=headers
        )
        try:
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise HttpError(f"response exceeds {max_bytes} bytes", url=url)
            return FetchedDocument(
                url=url,
                final_url=str(resp.url),
                status=resp.status_code,
                content_type=resp.headers.get("content-type"),
                content=bytes(buf),
                chain=chain,
                tls_verified=urlsplit(str(resp.url)).scheme == "https",
            )
        finally:
            resp.close()

    def download(
        self,
        url: str,
        sink: Sink,
        *,
        allow_http: bool = False,
        redirect_policy: RedirectPolicy | None = None,
        headers: dict[str, str] | None = None,
    ) -> Download:
        resp, chain = self._open(
            url, allow_http=allow_http, redirect_policy=redirect_policy, follow=True, headers=headers
        )
        try:
            clen_raw = resp.headers.get("content-length")
            clen = int(clen_raw) if clen_raw and clen_raw.isdigit() else None
            if clen is not None and clen > sink.max_bytes:
                raise HttpError(f"Content-Length {clen} exceeds the size limit", url=url)
            try:
                for chunk in resp.iter_bytes():
                    sink.write(chunk)
            except QuarantineError as e:
                raise HttpError(str(e), url=url) from e
            except httpx.HTTPError as e:
                raise HttpError(f"transfer interrupted: {e}", url=url) from e
            encoded = resp.headers.get("content-encoding", "identity").lower() not in ("", "identity")
            if clen is not None and not encoded and sink.size != clen:
                raise HttpError(f"received {sink.size} bytes, Content-Length said {clen}", url=url)
            return Download(
                url=url,
                final_url=str(resp.url),
                status=resp.status_code,
                content_type=resp.headers.get("content-type"),
                content_length=clen,
                chain=chain,
                tls_verified=urlsplit(str(resp.url)).scheme == "https",
            )
        finally:
            resp.close()


def _peek(resp: httpx.Response, n: int = 8192) -> bytes:
    try:
        out = bytearray()
        for chunk in resp.iter_bytes():
            out.extend(chunk)
            if len(out) >= n:
                break
        return bytes(out[:n])
    except httpx.HTTPError:
        return b""


def vendor_domain_policy(domains: list[str]) -> RedirectPolicy:
    def check(url: str) -> None:
        h = host_of(url)
        if not any(in_domain(h, d) for d in domains):
            raise HttpError(f"host {h} is outside the declared vendor domain(s) {', '.join(domains)}", url=url)

    return check

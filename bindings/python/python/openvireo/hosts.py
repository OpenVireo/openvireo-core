"""Ready-made Host parts, so a script needs no glue.

The core never opens a socket or a file, reads the clock or touches a keychain itself: it calls the
five Host interfaces (``HttpTransport``, ``SecureStore``, ``BlobCache``, ``Clock``, ``LogSink``).
This module implements each of them on the standard library (plus two optional extras), and
:func:`default_host` bundles them::

    import asyncio, openvireo
    from openvireo.hosts import default_host

    async def main():
        client = openvireo.OvClient(
            openvireo.ClientConfig(
                device=openvireo.DeviceInfo(id=None, name="script", platform=openvireo.Platform.CLI),
                offline=False,
                server=None,
            ),
            default_host(cache_dir="~/.cache/openvireo"),
        )
        account = await client.connect("https://accounts.openvireo.com", openvireo.CancelToken())

The async methods run on the event loop that awaits the core call. Blocking work (urllib, files,
the keyring) goes through :func:`asyncio.to_thread`, so it never stalls that loop.

Secrets that cross into Python (passwords, Secret Keys, stored session tokens) are plain ``bytes``.
Python can't wipe them; the core zeroizes its own copies.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import errno
import json
import logging
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from . import _core
from ._core import (
    BlobCache,
    ByteStream,
    CachedVault,
    Clock,
    Host,
    HttpHeader,
    HttpRequest,
    HttpResponse,
    HttpTransport,
    Level,
    LogSink,
    OpenedStream,
    OvError,
    OvErrorCode,
    SecureStore,
    TransportError,
    make_ov_error,
)

if TYPE_CHECKING:
    import http.client

    import httpx

__all__ = [
    "FileCache",
    "HttpxTransport",
    "KeyringStore",
    "LoggingSink",
    "MemoryCache",
    "MemoryStore",
    "SystemClock",
    "UrllibTransport",
    "default_host",
    "user_agent",
]

# The error variants are nested classes UniFFI attaches at import time, which type checkers can't see.
_TE: Any = TransportError

#: The logger :class:`LoggingSink` writes to.
LOGGER_NAME = "openvireo"


def user_agent() -> str:
    """The ``User-Agent`` the transports send unless the core sets one: ``openvireo-python/<core version>``."""
    return f"openvireo-python/{_core.version()}"


def _store_error(message: str) -> OvError:
    """An ``internal`` error for a store or cache that can't be read or written."""
    return make_ov_error(OvErrorCode.INTERNAL, message)


# ------------------------------------------------------------------------------------------ HTTP


def _transport_error_from_os(e: BaseException) -> Exception:
    """Maps a socket/urllib/ssl failure to the contract's ``TransportError``. The text never holds
    header values (only the exception's own message)."""
    if isinstance(e, urllib.error.URLError) and isinstance(e.reason, BaseException):
        e = e.reason
    if isinstance(e, (TimeoutError, socket.timeout)):
        return cast(Exception, _TE.Timeout())
    if isinstance(e, ssl.SSLError):
        return cast(Exception, _TE.Tls(str(e)))
    if isinstance(e, (ConnectionRefusedError, socket.gaierror)):
        return cast(Exception, _TE.Offline())
    if isinstance(e, OSError) and e.errno in (
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.EHOSTDOWN,
        errno.ECONNREFUSED,
        errno.EADDRNOTAVAIL,
    ):
        return cast(Exception, _TE.Offline())
    return cast(Exception, _TE.Other(f"{type(e).__name__}: {e}"))


class _NoDefaultContentType:
    """urllib adds ``Content-Type: application/x-www-form-urlencoded`` to any request with a body
    that has none. The contract says to send exactly the core's headers, so drop it again."""

    def do_request_(self, request: urllib.request.Request) -> urllib.request.Request:
        explicit = request.has_header("Content-type")
        request = super().do_request_(request)  # type: ignore[misc]
        if not explicit:
            request.unredirected_hdrs.pop("Content-type", None)
        return request


class _HTTPHandler(_NoDefaultContentType, urllib.request.HTTPHandler):
    http_request = _NoDefaultContentType.do_request_


class _HTTPSHandler(_NoDefaultContentType, urllib.request.HTTPSHandler):
    https_request = _NoDefaultContentType.do_request_


class _UrllibStream(ByteStream):
    """An open urllib response, read chunk by chunk on a worker thread."""

    def __init__(self, response: http.client.HTTPResponse, chunk_size: int) -> None:
        self._response = response
        self._chunk_size = chunk_size
        self._status = response.status
        self._closed = False
        self._lock = threading.Lock()

    def status(self) -> int:
        return self._status

    def _read(self) -> bytes | None:
        if self._closed:
            return None
        try:
            chunk = self._response.read1(self._chunk_size)
        except (OSError, ValueError, AttributeError) as e:
            # close() from another thread shuts the socket down under a blocked read.
            if self._closed:
                return None
            raise _transport_error_from_os(e) from e
        except Exception as e:  # http.client.IncompleteRead and friends
            if self._closed:
                return None
            raise _TE.Other(f"{type(e).__name__}: {e}") from e
        if not chunk:
            self.close()
            return None
        return chunk

    async def next_chunk(self) -> bytes | None:
        return await asyncio.to_thread(self._read)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        # Wake a read blocked on the socket: shutting the socket down makes recv() return.
        sock = getattr(getattr(getattr(self._response, "fp", None), "raw", None), "_sock", None)
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(Exception):
            self._response.close()


class UrllibTransport(HttpTransport):
    """HTTP on the standard library (``urllib.request``), run through :func:`asyncio.to_thread`.

    As the contract requires (``ov_core::host::HttpTransport``):

    - redirects are **not** followed: a 3xx comes back as a response, like any other status;
    - no cookies are stored or sent, and no credentials are added;
    - the core's headers are sent as given, plus ``User-Agent`` (:func:`user_agent`) when the core
      doesn't set one, and what ``http.client`` always adds (``Host``, ``Content-Length``,
      ``Accept-Encoding: identity``). Header values may be bearer tokens and are never logged;
    - any status is a response; only a failure to get one raises ``TransportError``
      (``Offline`` for refused connections and DNS failures, ``Timeout``, ``Tls``, ``Other``).

    ``timeout`` (seconds) bounds connecting and each read of :meth:`send`. Streams
    (:meth:`open_stream`, the SSE events) use ``stream_timeout``, ``None`` by default because an
    event stream can be quiet for a long time; closing the stream unblocks a pending read.
    Proxies come from the environment (``HTTPS_PROXY`` …) unless ``proxies`` is given (``{}`` for
    none). ``ssl_context`` replaces the default verified context.
    """

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        stream_timeout: float | None = None,
        ssl_context: ssl.SSLContext | None = None,
        proxies: dict[str, str] | None = None,
        chunk_size: int = 64 * 1024,
        user_agent: str | None = None,
    ) -> None:
        self._timeout = timeout
        self._stream_timeout = stream_timeout
        self._chunk_size = chunk_size
        self._user_agent = user_agent
        context = ssl_context or ssl.create_default_context()
        opener = urllib.request.OpenerDirector()
        # Only these handlers: no HTTPRedirectHandler (no redirects), no HTTPCookieProcessor (no
        # cookies), no HTTPErrorProcessor (4xx/5xx are responses, not exceptions).
        opener.add_handler(urllib.request.ProxyHandler(proxies))
        opener.add_handler(urllib.request.UnknownHandler())
        opener.add_handler(_HTTPHandler())
        opener.add_handler(_HTTPSHandler(context=context))
        opener.addheaders = []
        self._opener = opener

    def _request(self, req: HttpRequest) -> urllib.request.Request:
        r = urllib.request.Request(req.url, data=req.body, method=req.method.name)
        has_ua = False
        for h in req.headers:
            r.add_header(h.name, h.value)
            has_ua |= h.name.lower() == "user-agent"
        if not has_ua:
            r.add_header("User-Agent", self._user_agent or user_agent())
        return r

    def _open(self, req: HttpRequest, timeout: float | None) -> http.client.HTTPResponse:
        try:
            return cast("http.client.HTTPResponse", self._opener.open(self._request(req), timeout=timeout))
        except urllib.error.HTTPError as e:  # not raised without HTTPErrorProcessor; kept for safety
            return cast("http.client.HTTPResponse", e)
        except Exception as e:
            raise _transport_error_from_os(e) from e

    def _send(self, req: HttpRequest) -> HttpResponse:
        res = self._open(req, self._timeout)
        try:
            body = res.read()
        except Exception as e:
            raise _transport_error_from_os(e) from e
        finally:
            res.close()
        return HttpResponse(status=res.status, headers=_headers(res.getheaders()), body=body)

    async def send(self, req: HttpRequest) -> HttpResponse:
        return await asyncio.to_thread(self._send, req)

    async def open_stream(self, req: HttpRequest) -> OpenedStream:
        res = await asyncio.to_thread(self._open, req, self._stream_timeout)
        return OpenedStream(stream=_UrllibStream(res, self._chunk_size))


def _headers(pairs: Iterable[tuple[str, str]]) -> list[HttpHeader]:
    return [HttpHeader(name=k, value=v) for k, v in pairs]


class _HttpxStream(ByteStream):
    def __init__(self, response: httpx.Response, loop: asyncio.AbstractEventLoop) -> None:
        self._response = response
        self._loop = loop
        self._iter = response.aiter_raw()
        self._closed = False

    def status(self) -> int:
        return self._response.status_code

    async def next_chunk(self) -> bytes | None:
        import httpx

        if self._closed:
            return None
        try:
            chunk: bytes = await self._iter.__anext__()
        except StopAsyncIteration:
            self.close()
            return None
        except httpx.StreamClosed:
            return None
        except httpx.HTTPError as e:
            if self._closed:
                return None
            raise _httpx_error(e) from e
        return chunk

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(RuntimeError):  # the loop is already closed
            self._loop.call_soon_threadsafe(lambda: self._loop.create_task(self._response.aclose()))


def _httpx_error(e: BaseException) -> Exception:
    import httpx

    if isinstance(e, httpx.TimeoutException):
        return cast(Exception, _TE.Timeout())
    cause: BaseException | None = e
    while cause is not None:
        if isinstance(cause, ssl.SSLError):
            return cast(Exception, _TE.Tls(str(cause)))
        cause = cause.__cause__ or cause.__context__
    if isinstance(e, httpx.ConnectError):
        text = str(e).lower()
        if "ssl" in text or "certificate" in text:
            return cast(Exception, _TE.Tls(str(e)))
        return cast(Exception, _TE.Offline())
    return cast(Exception, _TE.Other(f"{type(e).__name__}: {e}"))


class HttpxTransport(HttpTransport):
    """Async HTTP on `httpx <https://www.python-httpx.org>`_ (``pip install openvireo[httpx]``).

    Same contract as :class:`UrllibTransport`: no redirects (``follow_redirects=False``), a cookie
    jar that refuses every cookie, the core's headers plus ``User-Agent`` and httpx's own
    (``Accept``, ``Accept-Encoding``, ``Connection``), every status a response. Streams are read
    natively (``aiter_raw``), with no worker thread.

    An ``httpx.AsyncClient`` is tied to the event loop that made its connections, so the transport
    keeps one client per running loop. Pass ``client`` to use your own (it must not follow redirects
    or keep cookies); ``timeout`` applies to the clients this class makes, streams read without one.
    """

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
        user_agent: str | None = None,
        **client_kwargs: Any,
    ) -> None:
        import httpx  # fails early, with the extra's name, when httpx isn't installed

        self._httpx = httpx
        self._timeout = timeout
        self._user_agent = user_agent
        self._client_kwargs = client_kwargs
        self._own: dict[int, tuple[asyncio.AbstractEventLoop, httpx.AsyncClient]] = {}
        self._given = client

    def _client(self) -> httpx.AsyncClient:
        if self._given is not None:
            return self._given
        loop = asyncio.get_running_loop()
        # Drop clients of loops that are gone (asyncio.run() per call in scripts).
        for key, (old, _) in list(self._own.items()):
            if old.is_closed():
                del self._own[key]
        entry = self._own.get(id(loop))
        if entry is None or entry[0] is not loop:
            import http.cookiejar

            jar = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))
            client = self._httpx.AsyncClient(
                follow_redirects=False,
                cookies=jar,
                timeout=self._timeout,
                headers={"User-Agent": self._user_agent or user_agent()},
                **self._client_kwargs,
            )
            entry = (loop, client)
            self._own[id(loop)] = entry
        return entry[1]

    def _build(self, client: httpx.AsyncClient, req: HttpRequest, *, stream: bool) -> httpx.Request:
        headers = [(h.name, h.value) for h in req.headers]
        r = client.build_request(
            req.method.name,
            req.url,
            headers=headers,
            content=req.body,
            timeout=self._httpx.Timeout(self._timeout, read=None) if stream else self._httpx.USE_CLIENT_DEFAULT,
        )
        return r

    async def send(self, req: HttpRequest) -> HttpResponse:
        client = self._client()
        try:
            res = await client.send(self._build(client, req, stream=False))
        except self._httpx.HTTPError as e:
            raise _httpx_error(e) from e
        client.cookies.clear()
        return HttpResponse(status=res.status_code, headers=_headers(res.headers.multi_items()), body=res.content)

    async def open_stream(self, req: HttpRequest) -> OpenedStream:
        client = self._client()
        try:
            res = await client.send(self._build(client, req, stream=True), stream=True)
        except self._httpx.HTTPError as e:
            raise _httpx_error(e) from e
        return OpenedStream(stream=_HttpxStream(res, asyncio.get_running_loop()))

    async def aclose(self) -> None:
        """Closes the clients this transport made on the running loop."""
        loop = asyncio.get_running_loop()
        entry = self._own.pop(id(loop), None)
        if entry is not None:
            await entry[1].aclose()


# ---------------------------------------------------------------------------------- SecureStore


class MemoryStore(SecureStore):
    """Secrets in a dict: gone when the process ends (each run signs in again). For tests and
    one-off scripts; use :class:`KeyringStore` to keep sessions and trusted Secret Keys."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}
        self._lock = threading.Lock()

    async def get(self, key: str) -> bytes | None:
        with self._lock:
            return self._data.get(key)

    async def set(self, key: str, value: bytes) -> None:
        with self._lock:
            self._data[key] = bytes(value)

    async def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


class KeyringStore(SecureStore):
    """Secrets in the OS keychain through `keyring <https://pypi.org/project/keyring/>`_
    (``pip install openvireo[keyring]``): the macOS Keychain, Windows Credential Locker, or the
    Secret Service on Linux. Each key is an entry of ``service``; values are stored base64-encoded.

    A keychain that can't be read raises ``OvError`` (code ``internal``), which the core treats
    differently from a missing value.
    """

    def __init__(self, service: str = "openvireo", *, backend: Any = None) -> None:
        import keyring  # fails early, with the extra's name, when keyring isn't installed

        self._keyring = keyring
        self._service = service
        self._backend = backend

    def _kr(self) -> Any:
        return self._backend or self._keyring.get_keyring()

    def _get(self, key: str) -> bytes | None:
        try:
            v = self._kr().get_password(self._service, key)
        except Exception as e:
            raise _store_error(f"keyring: can't read: {type(e).__name__}") from e
        return None if v is None else base64.b64decode(v)

    def _set(self, key: str, value: bytes) -> None:
        try:
            self._kr().set_password(self._service, key, base64.b64encode(value).decode("ascii"))
        except Exception as e:
            raise _store_error(f"keyring: can't write: {type(e).__name__}") from e

    def _delete(self, key: str) -> None:
        from keyring.errors import PasswordDeleteError

        try:
            self._kr().delete_password(self._service, key)
        except PasswordDeleteError:
            pass  # a missing key is not an error
        except Exception as e:
            raise _store_error(f"keyring: can't delete: {type(e).__name__}") from e

    async def get(self, key: str) -> bytes | None:
        return await asyncio.to_thread(self._get, key)

    async def set(self, key: str, value: bytes) -> None:
        await asyncio.to_thread(self._set, key, bytes(value))

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._delete, key)


# ------------------------------------------------------------------------------------ BlobCache


class MemoryCache(BlobCache):
    """The offline cache (SPEC §20) in dicts: nothing survives the process."""

    def __init__(self) -> None:
        self._vaults: dict[tuple[str, str], CachedVault] = {}
        self._meta: dict[tuple[str, str], bytes] = {}
        self._lock = threading.Lock()

    async def load(self, user_id: str, vault_id: str) -> CachedVault | None:
        with self._lock:
            return self._vaults.get((user_id, vault_id))

    async def save(self, user_id: str, vault_id: str, v: CachedVault) -> None:
        with self._lock:
            self._vaults[(user_id, vault_id)] = v

    async def remove(self, user_id: str, vault_id: str) -> None:
        with self._lock:
            self._vaults.pop((user_id, vault_id), None)

    async def list(self, user_id: str) -> list[str]:
        with self._lock:
            return sorted(v for (u, v) in self._vaults if u == user_id)

    async def load_meta(self, user_id: str, name: str) -> bytes | None:
        with self._lock:
            return self._meta.get((user_id, name))

    async def save_meta(self, user_id: str, name: str, value: bytes) -> None:
        with self._lock:
            self._meta[(user_id, name)] = bytes(value)

    async def clear_user(self, user_id: str) -> None:
        with self._lock:
            for k in [k for k in self._vaults if k[0] == user_id]:
                del self._vaults[k]
            for k in [k for k in self._meta if k[0] == user_id]:
                del self._meta[k]


def _b64(b: bytes | None) -> str | None:
    return None if b is None else base64.b64encode(b).decode("ascii")


def _unb64(s: str | None) -> bytes | None:
    return None if s is None else base64.b64decode(s)


class FileCache(BlobCache):
    """The offline cache (SPEC §20) as files under ``directory``.

    Everything the core caches is already ciphertext or public (vault blobs under the vault key,
    the wrapped keyset, the discovery document), so plain files are fine. Layout, with every id
    hex-encoded so no id can escape the folder::

        <directory>/<hex user id or "_device">/vaults/<hex vault id>.json
        <directory>/<hex user id or "_device">/meta/<hex name>

    Writes are atomic (a temporary file, then ``os.replace``); folders are created ``0700`` and
    files ``0600``.
    """

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self._dir = Path(directory).expanduser()

    @staticmethod
    def _enc(s: str) -> str:
        return s.encode("utf-8").hex()

    def _user_dir(self, user_id: str) -> Path:
        return self._dir / (self._enc(user_id) if user_id else "_device")

    def _write(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    @staticmethod
    def _read(path: Path) -> bytes | None:
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def _run(self, what: str, fn: Any, *args: Any) -> Any:
        try:
            return fn(*args)
        except OvError:
            raise
        except Exception as e:
            raise _store_error(f"file cache: can't {what}: {type(e).__name__}: {e}") from e

    def _load(self, user_id: str, vault_id: str) -> CachedVault | None:
        raw = self._read(self._user_dir(user_id) / "vaults" / f"{self._enc(vault_id)}.json")
        if raw is None:
            return None
        d = json.loads(raw)
        return CachedVault(
            state=_unb64(d["state"]) or b"",
            base=_unb64(d.get("base")),
            pending=_unb64(d.get("pending")),
            autofill=_unb64(d.get("autofill")),
        )

    def _save(self, user_id: str, vault_id: str, v: CachedVault) -> None:
        d = {"state": _b64(v.state), "base": _b64(v.base), "pending": _b64(v.pending), "autofill": _b64(v.autofill)}
        self._write(self._user_dir(user_id) / "vaults" / f"{self._enc(vault_id)}.json", json.dumps(d).encode())

    def _remove(self, user_id: str, vault_id: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            (self._user_dir(user_id) / "vaults" / f"{self._enc(vault_id)}.json").unlink()

    def _list(self, user_id: str) -> list[str]:
        d = self._user_dir(user_id) / "vaults"
        if not d.is_dir():
            return []
        out = []
        for p in d.iterdir():
            if p.suffix == ".json" and not p.name.startswith("."):
                out.append(bytes.fromhex(p.stem).decode("utf-8"))
        return sorted(out)

    def _save_meta(self, user_id: str, name: str, value: bytes) -> None:
        self._write(self._user_dir(user_id) / "meta" / self._enc(name), value)

    def _clear(self, user_id: str) -> None:
        shutil.rmtree(self._user_dir(user_id), ignore_errors=True)

    async def load(self, user_id: str, vault_id: str) -> CachedVault | None:
        return cast("CachedVault | None", await asyncio.to_thread(self._run, "read", self._load, user_id, vault_id))

    async def save(self, user_id: str, vault_id: str, v: CachedVault) -> None:
        await asyncio.to_thread(self._run, "write", self._save, user_id, vault_id, v)

    async def remove(self, user_id: str, vault_id: str) -> None:
        await asyncio.to_thread(self._run, "remove", self._remove, user_id, vault_id)

    async def list(self, user_id: str) -> list[str]:
        return cast("list[str]", await asyncio.to_thread(self._run, "list", self._list, user_id))

    async def load_meta(self, user_id: str, name: str) -> bytes | None:
        path = self._user_dir(user_id) / "meta" / self._enc(name)
        return cast("bytes | None", await asyncio.to_thread(self._run, "read", self._read, path))

    async def save_meta(self, user_id: str, name: str, value: bytes) -> None:
        await asyncio.to_thread(self._run, "write", self._save_meta, user_id, name, bytes(value))

    async def clear_user(self, user_id: str) -> None:
        await asyncio.to_thread(self._run, "clear", self._clear, user_id)


# ---------------------------------------------------------------------------------- clock, logs


class SystemClock(Clock):
    """The wall clock (``time.time_ns()``)."""

    def now_unix_ms(self) -> int:
        return time.time_ns() // 1_000_000


#: ``logging`` level for each core level (``TRACE`` is 5, below ``DEBUG``).
_LEVELS = {
    Level.ERROR: logging.ERROR,
    Level.WARN: logging.WARNING,
    Level.INFO: logging.INFO,
    Level.DEBUG: logging.DEBUG,
    Level.TRACE: 5,
}


class LoggingSink(LogSink):
    """Forwards the core's log lines to ``logging.getLogger("openvireo")`` (or ``logger``). The
    core's module (e.g. ``ov_sync``) is in the record as ``ov_target``. The core never logs
    secrets. It may call this from any thread."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(LOGGER_NAME)

    def log(self, level: Level, target: str, msg: str) -> None:
        lvl = _LEVELS.get(level, logging.INFO)
        if self._logger.isEnabledFor(lvl):
            self._logger.log(lvl, "%s: %s", target, msg, extra={"ov_target": target})


# --------------------------------------------------------------------------------- default_host


def default_transport() -> HttpTransport:
    """:class:`HttpxTransport` when httpx is installed, else :class:`UrllibTransport`."""
    try:
        import httpx  # noqa: F401
    except ImportError:
        return UrllibTransport()
    return HttpxTransport()


def default_host(
    *,
    http: HttpTransport | None = None,
    store: SecureStore | None = None,
    cache: BlobCache | None = None,
    clock: Clock | None = None,
    log: LogSink | None = None,
    cache_dir: str | os.PathLike[str] | None = None,
) -> Host:
    """A ``Host`` from the parts given, with defaults for the rest:

    - ``http``: :func:`default_transport` (httpx if installed, else urllib);
    - ``store``: :class:`MemoryStore` (pass :class:`KeyringStore` to keep sessions across runs);
    - ``cache``: :class:`FileCache` on ``cache_dir`` if given, else :class:`MemoryCache`;
    - ``clock``: :class:`SystemClock`; ``log``: :class:`LoggingSink`.
    """
    if cache is None:
        cache = FileCache(cache_dir) if cache_dir is not None else MemoryCache()
    return Host(
        http or default_transport(),
        store or MemoryStore(),
        cache,
        clock or SystemClock(),
        log or LoggingSink(),
    )

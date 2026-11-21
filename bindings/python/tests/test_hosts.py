"""Unit tests for openvireo.hosts: the transports against a local http.server (no redirects, exact
headers, every status a response, streaming, errors), the stores, caches, clock and log sink, and
how UniFFI's async foreign traits behave (cancellation, several event loops, threads)."""

from __future__ import annotations

import asyncio
import http.server
import logging
import os
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field

import openvireo as ov
import pytest
from openvireo import hosts


@dataclass
class Seen:
    method: str
    path: str
    headers: list[tuple[str, str]]
    body: bytes


@dataclass
class Server:
    url: str
    seen: list[Seen] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_state: Server

    def log_message(self, *args: object) -> None:
        pass

    def _record(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        self.server_state.seen.append(Seen(self.command, self.path, list(self.headers.items()), body))

    def _reply(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _route(self) -> None:
        self._record()
        p = self.path
        if p.startswith("/redirect"):
            self._reply(302, b"moved", {"Location": "/target"})
        elif p.startswith("/target"):
            self._reply(200, b"followed!")
        elif p.startswith("/status/"):
            code = int(p.rsplit("/", 1)[1])
            self._reply(code, b'{"error":"x","code":"y"}', {"Content-Type": "application/json"})
        elif p.startswith("/cookie"):
            self._reply(200, b"ok", {"Set-Cookie": "sid=1; Path=/"})
        elif p.startswith("/multi"):
            self.send_response(200)
            self.send_header("X-Dup", "a")
            self.send_header("X-Dup", "b")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif p.startswith("/slow"):
            time.sleep(1.0)
            self._reply(200, b"late")
        elif p.startswith("/sse"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"data: 1\n\n")
            self.wfile.flush()
            # The second event only after the test has read the first: proves chunks arrive
            # as they are written, not at the end.
            self.server_state.release.wait(5)
            self.wfile.write(b"data: 2\n\n")
            self.wfile.flush()
            if p.startswith("/sse-hang"):
                self.server_state.release.clear()
                self.server_state.release.wait(10)
            self.close_connection = True
        else:
            self._reply(200, b"hello " + self.server_state.seen[-1].body, {"X-Reply": "1"})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _route


@pytest.fixture
def server() -> Iterator[Server]:
    state = Server(url="")

    class H(Handler):
        server_state = state

    class Quiet(http.server.ThreadingHTTPServer):
        def handle_error(self, request: object, client_address: object) -> None:
            pass  # a client that closed a stream early

    httpd = Quiet(("127.0.0.1", 0), H)
    httpd.daemon_threads = True
    state.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    t.start()
    yield state
    state.release.set()
    httpd.shutdown()
    httpd.server_close()


def req(
    method: ov.Method, url: str, headers: dict[str, str] | None = None, body: bytes | None = None
) -> ov.HttpRequest:
    return ov.HttpRequest(
        method=method,
        url=url,
        headers=[ov.HttpHeader(name=k, value=v) for k, v in (headers or {}).items()],
        body=body,
        keepalive=False,
    )


def header(r: ov.HttpResponse, name: str) -> str | None:
    return next((h.value for h in r.headers if h.name.lower() == name.lower()), None)


def seen_header(s: Seen, name: str) -> str | None:
    return next((v for k, v in s.headers if k.lower() == name.lower()), None)


@pytest.fixture(params=["urllib", "httpx"])
def transport(request: pytest.FixtureRequest) -> ov.HttpTransport:
    if request.param == "urllib":
        return hosts.UrllibTransport(timeout=0.5, proxies={})
    pytest.importorskip("httpx")
    return hosts.HttpxTransport(timeout=0.5, trust_env=False)


# ------------------------------------------------------------------------------------ transports


async def test_sends_the_core_headers_and_body(server: Server, transport: ov.HttpTransport) -> None:
    r = await transport.send(
        req(ov.Method.POST, f"{server.url}/echo?q=1", {"Authorization": "Bearer t", "If-Match": '"e1"'}, b"body")
    )
    assert r.status == 200
    assert r.body == b"hello body"
    assert header(r, "x-reply") == "1"
    s = server.seen[-1]
    assert (s.method, s.path, s.body) == ("POST", "/echo?q=1", b"body")
    assert seen_header(s, "authorization") == "Bearer t"
    assert seen_header(s, "if-match") == '"e1"'
    assert seen_header(s, "user-agent") == hosts.user_agent()
    # Exactly the core's headers: no Content-Type invented for the body, no cookies.
    assert seen_header(s, "content-type") is None
    assert seen_header(s, "cookie") is None


async def test_the_core_user_agent_wins(server: Server, transport: ov.HttpTransport) -> None:
    await transport.send(req(ov.Method.GET, f"{server.url}/x", {"User-Agent": "openvireo/9"}))
    assert seen_header(server.seen[-1], "user-agent") == "openvireo/9"


async def test_does_not_follow_redirects(server: Server, transport: ov.HttpTransport) -> None:
    r = await transport.send(req(ov.Method.POST, f"{server.url}/redirect", body=b"x"))
    assert r.status == 302
    assert header(r, "location") == "/target"
    assert r.body == b"moved"
    assert [s.path for s in server.seen] == ["/redirect"]


@pytest.mark.parametrize("code", [400, 401, 404, 409, 412, 429, 500, 503])
async def test_every_status_is_a_response(server: Server, transport: ov.HttpTransport, code: int) -> None:
    r = await transport.send(req(ov.Method.GET, f"{server.url}/status/{code}"))
    assert r.status == code
    assert r.body == b'{"error":"x","code":"y"}'


async def test_head_has_no_body(server: Server, transport: ov.HttpTransport) -> None:
    r = await transport.send(req(ov.Method.HEAD, f"{server.url}/x"))
    assert (r.status, r.body) == (200, b"")


async def test_methods(server: Server, transport: ov.HttpTransport) -> None:
    for m in (ov.Method.GET, ov.Method.PUT, ov.Method.PATCH, ov.Method.DELETE):
        await transport.send(req(m, f"{server.url}/m", body=b"b" if m != ov.Method.GET else None))
    assert [s.method for s in server.seen] == ["GET", "PUT", "PATCH", "DELETE"]


async def test_keeps_no_cookies(server: Server, transport: ov.HttpTransport) -> None:
    r = await transport.send(req(ov.Method.GET, f"{server.url}/cookie"))
    assert header(r, "set-cookie") == "sid=1; Path=/"
    await transport.send(req(ov.Method.GET, f"{server.url}/after"))
    assert seen_header(server.seen[-1], "cookie") is None


async def test_repeated_headers_stay_in_order(server: Server, transport: ov.HttpTransport) -> None:
    r = await transport.send(req(ov.Method.GET, f"{server.url}/multi"))
    assert [h.value for h in r.headers if h.name.lower() == "x-dup"] == ["a", "b"]


async def test_a_refused_connection_is_offline(transport: ov.HttpTransport) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(ov.TransportError.Offline):
        await transport.send(req(ov.Method.GET, f"http://127.0.0.1:{port}/"))


async def test_a_slow_server_times_out(server: Server, transport: ov.HttpTransport) -> None:
    with pytest.raises(ov.TransportError.Timeout):
        await transport.send(req(ov.Method.GET, f"{server.url}/slow"))


async def test_streams_chunks_as_they_arrive(server: Server, transport: ov.HttpTransport) -> None:
    opened = await transport.open_stream(req(ov.Method.GET, f"{server.url}/sse", {"Accept": "text/event-stream"}))
    s = opened.stream
    assert s.status() == 200
    first = await asyncio.wait_for(s.next_chunk(), 5)
    assert first == b"data: 1\n\n"
    server.release.set()
    rest = b""
    while (c := await asyncio.wait_for(s.next_chunk(), 5)) is not None:
        rest += c
    assert rest == b"data: 2\n\n"
    s.close()
    assert await s.next_chunk() is None


async def test_close_unblocks_a_pending_read(server: Server, transport: ov.HttpTransport) -> None:
    opened = await transport.open_stream(req(ov.Method.GET, f"{server.url}/sse-hang"))
    s = opened.stream
    assert await asyncio.wait_for(s.next_chunk(), 5) == b"data: 1\n\n"
    server.release.set()
    assert await asyncio.wait_for(s.next_chunk(), 5) == b"data: 2\n\n"
    pending = asyncio.ensure_future(s.next_chunk())  # the server now holds the connection open
    await asyncio.sleep(0.1)
    s.close()
    assert await asyncio.wait_for(pending, 5) is None
    assert await s.next_chunk() is None


async def test_an_error_status_stream_yields_the_body(server: Server, transport: ov.HttpTransport) -> None:
    opened = await transport.open_stream(req(ov.Method.GET, f"{server.url}/status/401"))
    assert opened.stream.status() == 401
    body = b""
    while (c := await opened.stream.next_chunk()) is not None:
        body += c
    assert body == b'{"error":"x","code":"y"}'


# ------------------------------------------------------------------------- stores and caches


async def test_memory_store() -> None:
    s = hosts.MemoryStore()
    assert await s.get("k") is None
    await s.set("k", b"v")
    assert await s.get("k") == b"v"
    await s.delete("k")
    await s.delete("k")  # missing is fine
    assert await s.get("k") is None


async def test_keyring_store_with_a_memory_backend() -> None:
    keyring = pytest.importorskip("keyring")
    from keyring.backend import KeyringBackend
    from keyring.errors import PasswordDeleteError

    class Mem(KeyringBackend):
        priority = 1  # type: ignore[assignment]

        def __init__(self) -> None:
            self.d: dict[tuple[str, str], str] = {}

        def get_password(self, service: str, username: str) -> str | None:
            return self.d.get((service, username))

        def set_password(self, service: str, username: str, password: str) -> None:
            self.d[(service, username)] = password

        def delete_password(self, service: str, username: str) -> None:
            if (service, username) not in self.d:
                raise PasswordDeleteError(username)
            del self.d[(service, username)]

    assert keyring
    backend = Mem()
    s = hosts.KeyringStore("openvireo-test", backend=backend)
    await s.set("secret_key:h:u", b"\x00\xffbytes")
    assert await s.get("secret_key:h:u") == b"\x00\xffbytes"
    assert ("openvireo-test", "secret_key:h:u") in backend.d
    await s.delete("secret_key:h:u")
    await s.delete("secret_key:h:u")
    assert await s.get("secret_key:h:u") is None

    class Locked(Mem):
        def get_password(self, service: str, username: str) -> str | None:
            raise RuntimeError("locked")

    with pytest.raises(ov.OvError) as e:
        await hosts.KeyringStore(backend=Locked()).get("x")
    assert e.value.code == ov.OvErrorCode.INTERNAL


def cached(n: int) -> ov.CachedVault:
    return ov.CachedVault(state=bytes([n]), base=b"base" if n % 2 else None, pending=None, autofill=b"af")


@pytest.mark.parametrize("kind", ["memory", "file"])
async def test_caches(kind: str, tmp_path: os.PathLike[str]) -> None:
    c: ov.BlobCache = hosts.MemoryCache() if kind == "memory" else hosts.FileCache(tmp_path)
    assert await c.load("u1", "v1") is None
    await c.save("u1", "v1", cached(1))
    await c.save("u1", "../v/2", cached(2))  # an odd id stays inside the folder
    await c.save("u2", "v1", cached(3))
    got = await c.load("u1", "v1")
    assert got is not None and (got.state, got.base, got.pending, got.autofill) == (b"\x01", b"base", None, b"af")
    assert await c.list("u1") == sorted(["v1", "../v/2"])
    await c.remove("u1", "v1")
    await c.remove("u1", "v1")
    assert await c.list("u1") == ["../v/2"]
    await c.save_meta("", "config:https://x", b"{}")
    await c.save_meta("u1", "profile", b"p")
    assert await c.load_meta("", "config:https://x") == b"{}"
    assert await c.load_meta("u1", "profile") == b"p"
    assert await c.load_meta("u1", "nope") is None
    await c.clear_user("u1")
    assert await c.list("u1") == []
    assert await c.load_meta("u1", "profile") is None
    assert await c.load("u2", "v1") is not None
    assert await c.load_meta("", "config:https://x") == b"{}"
    if kind == "file":
        files = [os.path.join(d, f) for d, _, fs in os.walk(tmp_path) for f in fs]
        assert files and all(os.path.realpath(f).startswith(os.path.realpath(tmp_path)) for f in files)
        assert all(os.stat(f).st_mode & 0o077 == 0 for f in files)


def test_system_clock() -> None:
    assert abs(hosts.SystemClock().now_unix_ms() - time.time() * 1000) < 1000


def test_logging_sink(caplog: pytest.LogCaptureFixture) -> None:
    sink = hosts.LoggingSink()
    with caplog.at_level(5, logger="openvireo"):
        sink.log(ov.Level.WARN, "ov_sync", "merged 3")
        sink.log(ov.Level.TRACE, "ov_http", "detail")
    assert [(r.levelno, r.getMessage(), r.ov_target) for r in caplog.records] == [  # type: ignore[attr-defined]
        (logging.WARNING, "ov_sync: merged 3", "ov_sync"),
        (5, "ov_http: detail", "ov_http"),
    ]


def test_default_host_picks_parts(tmp_path: os.PathLike[str]) -> None:
    assert isinstance(hosts.default_transport(), hosts.HttpxTransport | hosts.UrllibTransport)
    assert isinstance(hosts.default_host(cache_dir=tmp_path), ov.Host)


# ----------------------------------------------------------- UniFFI async foreign trait behaviour


class HangingHttp(ov.HttpTransport):
    """A send that never finishes, to see what the core does when its caller gives up."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def send(self, req: ov.HttpRequest) -> ov.HttpResponse:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("unreachable")

    async def open_stream(self, req: ov.HttpRequest) -> ov.OpenedStream:
        raise ov.TransportError.Offline()


def client_on(http: ov.HttpTransport) -> ov.OvClient:
    config = ov.ClientConfig(
        device=ov.DeviceInfo(id=None, name="t", platform=ov.Platform.CLI), offline=False, server=None
    )
    return ov.OvClient(config, hosts.default_host(http=http))


async def test_cancelling_the_python_task_cancels_the_host_call() -> None:
    h = HangingHttp()
    task = asyncio.ensure_future(client_on(h).discover("https://example.test", ov.CancelToken()))
    await asyncio.wait_for(h.started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(50):
        if h.cancelled:
            break
        await asyncio.sleep(0.01)
    assert h.cancelled  # the Rust future was dropped, and UniFFI cancelled the Python coroutine


async def test_a_cancel_token_cancels_the_host_call() -> None:
    h = HangingHttp()
    token = ov.CancelToken()
    task = asyncio.ensure_future(client_on(h).discover("https://example.test", token))
    await asyncio.wait_for(h.started.wait(), 5)
    token.cancel()
    with pytest.raises(ov.OvError) as e:
        await asyncio.wait_for(task, 5)
    assert e.value.code == ov.OvErrorCode.ABORTED


def test_one_client_across_event_loops_and_threads(server: Server) -> None:
    """The same client and transport, used from several asyncio.run() loops in turn and from
    threads that each run their own loop at once: each host call runs on the loop that awaits the
    core call."""
    c = client_on(hosts.UrllibTransport(timeout=2, proxies={}))

    async def one() -> ov.OvErrorCode:
        try:
            await c.discover(server.url, ov.CancelToken())
        except ov.OvError as e:
            return e.code
        return ov.OvErrorCode.INTERNAL

    # The local server answers discovery with "hello", which isn't a discovery document.
    first = asyncio.run(one())
    assert first != ov.OvErrorCode.NETWORK_ERROR
    assert asyncio.run(one()) == first
    results: list[ov.OvErrorCode] = []

    def worker() -> None:
        results.append(asyncio.run(one()))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert results == [first] * 4


async def test_many_concurrent_core_calls(server: Server) -> None:
    c = client_on(hosts.UrllibTransport(timeout=5, proxies={}))

    async def one() -> str:
        try:
            await c.discover(server.url, ov.CancelToken())
        except ov.OvError as e:
            return e.wire_code
        return "ok"

    out = await asyncio.gather(*(one() for _ in range(25)))
    assert len(set(out)) == 1
    assert len(server.seen) == 25

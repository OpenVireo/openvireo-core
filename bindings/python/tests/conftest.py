"""Fixtures: the testkit relay (the in-memory auth + sync servers on loopback HTTP) and devices.

The relay is `crates/ov-testkit/examples/http_relay.rs`. `cargo xtask python --smoke` builds it and
sets ``OV_TESTKIT_RELAY`` to its path; without it the live smoke tests are skipped.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass

import openvireo as ov
import pytest
from openvireo import hosts

RELAY_URL_HEADER = "x-ov-relay-url"


@dataclass
class Relay:
    url: str
    issuer: str
    api: str
    sync: str


@pytest.fixture(scope="session")
def relay() -> Iterator[Relay]:
    path = os.environ.get("OV_TESTKIT_RELAY")
    if not path:
        pytest.skip("OV_TESTKIT_RELAY is not set (run `cargo xtask python --smoke`)")
    proc = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout is not None
        info = json.loads(proc.stdout.readline())
        yield Relay(info["relay"], info["issuer"], info["api"], info["sync"])
    finally:
        if proc.stdin:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class RelayTransport(ov.HttpTransport):
    """Sends the core's requests to the relay: the path goes to ``http://127.0.0.1:<port>`` and the
    real URL (``https://auth.test/…``) rides in ``x-ov-relay-url``. Everything else is the wrapped
    transport's own behaviour, so the smoke runs the real UrllibTransport / HttpxTransport."""

    def __init__(self, inner: ov.HttpTransport, base: str) -> None:
        self.inner = inner
        self.base = base.rstrip("/")
        self.urls: list[str] = []

    def _rewrite(self, req: ov.HttpRequest) -> ov.HttpRequest:
        self.urls.append(req.url)
        rest = req.url.split("://", 1)[1]
        path = rest[rest.find("/") :] if "/" in rest else "/"
        headers = [*req.headers, ov.HttpHeader(name=RELAY_URL_HEADER, value=req.url)]
        return ov.HttpRequest(
            method=req.method, url=self.base + path, headers=headers, body=req.body, keepalive=req.keepalive
        )

    async def send(self, req: ov.HttpRequest) -> ov.HttpResponse:
        return await self.inner.send(self._rewrite(req))

    async def open_stream(self, req: ov.HttpRequest) -> ov.OpenedStream:
        return await self.inner.open_stream(self._rewrite(req))


def make_transport(kind: str) -> ov.HttpTransport:
    if kind == "urllib":
        return hosts.UrllibTransport(timeout=10)
    pytest.importorskip("httpx")
    return hosts.HttpxTransport(timeout=10)


@pytest.fixture(params=["urllib", "httpx"])
def transport_kind(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@dataclass
class Device:
    client: ov.OvClient
    http: RelayTransport
    store: hosts.MemoryStore


@pytest.fixture
def new_device(relay: Relay, transport_kind: str, tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    """Makes a new device on the relay: its own store, a FileCache in a fresh folder, the system
    clock and the logging sink, as a script would set it up with ``default_host``."""

    def make(name: str = "py-smoke") -> Device:
        http = RelayTransport(make_transport(transport_kind), relay.url)
        store = hosts.MemoryStore()
        host = hosts.default_host(http=http, store=store, cache_dir=tmp_path_factory.mktemp("cache"))
        config = ov.ClientConfig(
            device=ov.DeviceInfo(id=None, name=name, platform=ov.Platform.CLI), offline=False, server=None
        )
        return Device(ov.OvClient(config, host), http, store)

    return make

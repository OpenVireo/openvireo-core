"""The Swift SmokeTests' steps on the Python binding, plus a live flow against the testkit servers.

The live tests run every Host call through Python: the core (Rust) awaits the Python
``HttpTransport`` (UrllibTransport or HttpxTransport, behind ``RelayTransport``), which reaches the
in-memory servers over a real loopback socket. The event stream test covers ``open_stream`` /
``next_chunk`` across that socket.
"""

from __future__ import annotations

import asyncio

import openvireo as ov
import pytest
from openvireo import hosts

KDF = ov.KdfOverrides(m=19456, t=2, p=1)  # the SDK tests' cheap KDF


def entry_input(fields: dict[str, str]) -> ov.EntryInput:
    return ov.EntryInput(
        fields=[ov.FieldInput(name=k, value=v.encode(), protected=None) for k, v in fields.items()],
        remove_fields=[],
        tags=None,
        icon_id=None,
        expiry=ov.EntryExpiry.KEEP(),
    )


def field(rec: ov.EntryRecord, name: str) -> bytes:
    return next((f.value for f in rec.fields if f.name == name), b"")


def find_title(v: ov.Vault, title: str) -> ov.EntryRecord:
    s = next(e for e in v.entries(False) if e.title == title)
    return v.entry(s.id)


async def register(dev, email: str, password: str, relay) -> tuple[ov.Account, ov.NewAccount]:  # type: ignore[no-untyped-def]
    a = await dev.client.connect(relay.issuer, ov.CancelToken())  # an explicit token still works
    kit = await a.register(ov.RegisterInput(email=email, password=password.encode(), kdf=KDF, trust_device=True))
    return a, kit


async def login(dev, relay, email: str, password: str, secret_key: bytes | None) -> ov.Account:  # type: ignore[no-untyped-def]
    a = await dev.client.connect(relay.issuer)
    step = await a.login(
        ov.LoginInput(email=email, password=password.encode(), secret_key=secret_key, totp=None, trust_device=True),
    )
    assert isinstance(step, ov.LoginStep.UNLOCKED), step
    return a


# ------------------------------------------------------------------ SmokeTests.swift (no servers)


def test_version() -> None:
    assert len(ov.version().split(".")) == 3
    assert ov.__version__ == ov.version()


def test_sha256() -> None:
    assert ov.sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_aead_round_trip_and_error_codes() -> None:
    key, nonce = bytes([7]) * 32, bytes([9]) * 24
    ct = ov.aead_encrypt(key, nonce, b"hi", b"")
    assert ov.aead_decrypt(key, nonce, ct, b"") == b"hi"
    with pytest.raises(ov.OvError) as e:
        ov.aead_decrypt(bytes([8]) * 32, nonce, ct, b"")
    assert e.value.code == ov.OvErrorCode.DECRYPTION_FAILED
    assert e.value.wire_code == "decryption_failed"


def test_facade_free_function() -> None:
    assert ov.default_share_fields() == ["UserName", "Password", "URL"]


def test_wire_codes() -> None:
    assert ov.error_code_wire(ov.OvErrorCode.PLAN_LIMIT) == "plan_limit"
    assert ov.error_code_from_wire("plan_limit") == ov.OvErrorCode.PLAN_LIMIT
    assert ov.error_code_from_wire("nope") is None
    assert ov.make_ov_error(ov.OvErrorCode.ABORTED, "x").wire_code == "aborted"


def test_opaque_test_server_steps_are_in_the_smoke_build() -> None:
    # `cargo xtask python --smoke` builds with `test-server`; release wheels don't.
    if not ov.opaque_has_test_server():
        pytest.skip("built without test-server")
    ids = ov.opaque_ids("  Alice@Example.com ", "https://accounts.openvireo.example")
    start = ov.opaque_start_registration("pw", None)
    srv = ov.opaque_server_registration_response(start.request, None)
    fin = ov.opaque_finish_registration(start.state, srv.response, ids, None)
    stored = ov.opaque_server_store_record(srv.setup, fin.record)
    ls = ov.opaque_start_login("pw", None)
    cr = ov.opaque_server_credential_response(ls.ke1, stored, ids, None, None)
    lf = ov.opaque_finish_login(ls.state, cr.ke2, ids, None, None)
    assert ov.opaque_server_user_auth(cr.state, lf.auth_u) == lf.session_key


# ------------------------------------------------------------------ HostTests.swift (fake hosts)


class OfflineHttp(ov.HttpTransport):
    async def send(self, req: ov.HttpRequest) -> ov.HttpResponse:
        raise ov.TransportError.Offline()

    async def open_stream(self, req: ov.HttpRequest) -> ov.OpenedStream:
        raise ov.TransportError.Offline()


class BrokenHttp(ov.HttpTransport):
    """Throws something that isn't a TransportError: the core sees `network_error` with the reason."""

    async def send(self, req: ov.HttpRequest) -> ov.HttpResponse:
        raise RuntimeError("boom")

    async def open_stream(self, req: ov.HttpRequest) -> ov.OpenedStream:
        raise RuntimeError("boom")


def offline_client(http: ov.HttpTransport | None = None) -> ov.OvClient:
    host = hosts.default_host(http=http or OfflineHttp())
    config = ov.ClientConfig(
        device=ov.DeviceInfo(id=None, name="smoke", platform=ov.Platform.CLI), offline=False, server=None
    )
    return ov.OvClient(config, host)


def test_client_keeps_its_config() -> None:
    config = offline_client().config()
    assert config.device.name == "smoke"
    assert config.device.platform == ov.Platform.CLI


async def test_async_call_uses_the_host() -> None:
    with pytest.raises(ov.OvError) as e:
        await offline_client().discover("https://example.test")
    assert e.value.code == ov.OvErrorCode.NETWORK_ERROR


async def test_a_host_exception_becomes_an_error_not_a_crash() -> None:
    with pytest.raises(ov.OvError) as e:
        await offline_client(BrokenHttp()).discover("https://example.test")
    assert e.value.code == ov.OvErrorCode.NETWORK_ERROR
    assert "boom" in e.value.message


async def test_local_vault_round_trip() -> None:
    pw = ov.KdbxCredentials(password="pw ✓".encode(), key_file=None)
    v = await offline_client().create_local("Home", pw)
    work = v.add_group(None, "Work")
    entry_id = v.add_entry(work, entry_input({"Title": "VPN", "Password": "s3cret"}))
    data = await v.save_local()
    back = await ov.Vault.open_local(data, pw)
    rec = back.entry(entry_id)
    assert rec.group_path == ["Work"]
    assert field(rec, "Password") == b"s3cret"
    wrong = ov.KdbxCredentials(password=b"no", key_file=None)
    with pytest.raises(ov.OvError) as e:
        await ov.Vault.open_local(data, wrong)
    assert e.value.code == ov.OvErrorCode.VAULT_KEY_MISMATCH


async def test_cancel_token_aborts() -> None:
    t = ov.CancelToken()
    t.cancel()
    assert t.is_cancelled()
    with pytest.raises(ov.OvError) as e:
        await offline_client().discover("https://example.test", t)
    assert e.value.code == ov.OvErrorCode.ABORTED


# ------------------------------------------------------------------ live: the testkit servers


async def test_register_vault_sync_second_device(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    email = f"alice-{id(new_device)}@example.com"
    dev = new_device()
    a, kit = await register(dev, email, "correct horse ü", relay)
    assert kit.emergency_kit.email == email
    assert a.server_config().sync == relay.sync
    vault = await a.create_vault("Personal", None)
    vault.add_entry(vault.root_group_id(), entry_input({"Title": "GitHub", "Password": "gh-pass"}))
    report = await vault.sync(ov.SyncOptions(local_changed=True))
    assert report is not None
    assert vault.etag() is not None
    # Everything went through the Python transport.
    assert any(u.startswith("https://auth.test/") for u in dev.http.urls)
    assert any(u.startswith("https://sync.test/") for u in dev.http.urls)
    # The session and trusted Secret Key landed in the Python store.
    assert dev.store._data

    # Second device: without the Secret Key the first time it's refused, with it the vault opens.
    dev2 = new_device("second")
    a2 = await dev2.client.connect(relay.issuer)
    with pytest.raises(ov.OvError) as e:
        await a2.login(
            ov.LoginInput(
                email=email, password="correct horse ü".encode(), secret_key=None, totp=None, trust_device=True
            ),
        )
    assert e.value.code == ov.OvErrorCode.INVALID_SECRET_KEY
    a2 = await login(dev2, relay, email, "correct horse ü", kit.secret_key)
    with pytest.raises(ov.OvError) as e:
        stopped = ov.CancelToken()
        stopped.cancel()
        await a2.vaults(cancel=stopped)
    assert e.value.code == ov.OvErrorCode.ABORTED
    names = [v.name for v in await a2.vaults()]
    assert names == ["Personal"]
    v2 = await a2.open_vault(vault.id())
    assert field(find_title(v2, "GitHub"), "Password") == b"gh-pass"

    # An edit on the second device reaches the first after a sync.
    v2.add_entry(v2.root_group_id(), entry_input({"Title": "Bank", "Password": "b"}))
    await v2.sync(ov.SyncOptions(local_changed=True))
    await vault.sync(ov.SyncOptions(local_changed=False))
    assert sorted(e.title for e in vault.entries(False)) == ["Bank", "GitHub"]


async def test_error_codes_from_the_server(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    email = f"err-{id(new_device)}@example.com"
    _, kit = await register(new_device(), email, "pw", relay)
    a2 = await new_device().client.connect(relay.issuer)
    with pytest.raises(ov.OvError) as e:
        await a2.login(
            ov.LoginInput(email=email, password=b"nope", secret_key=kit.secret_key, totp=None, trust_device=True)
        )
    assert (e.value.code, e.value.status) == (ov.OvErrorCode.UNAUTHORIZED, 401)
    assert e.value.wire_code == "unauthorized"
    # A host that can't be reached is a network error (the relay answers 502 for an unknown host;
    # a refused port is Offline in the transport tests).
    with pytest.raises(ov.OvError) as e:
        await new_device().client.discover("https://nowhere.test")
    assert e.value.code in (ov.OvErrorCode.SERVER_ERROR, ov.OvErrorCode.NETWORK_ERROR)


async def test_share_link_open_without_an_account_then_revoke(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    a, _ = await register(new_device(), f"share-{id(new_device)}@example.com", "pw", relay)
    api = a.server_config().api
    payload = ov.text_share_payload(b"the secret", "Note", None)
    created = await a.create_share(
        payload, ov.ShareOptions(expires_in=3600, max_opens=2, passcode=None, vault_id=None, entry_id=None)
    )
    assert b"#" in created.url

    anon = new_device("anon").client
    info = await anon.share_info(api, created.id)
    assert info.opens_left == 2 and info.kdf is None
    opened = await anon.open_share(api, created.url, None, info)
    assert opened.payload.fields[0].value == b"the secret"
    assert opened.opens_left == 1

    await a.revoke_share(created.id)
    with pytest.raises(ov.OvError) as e:
        await anon.share_info(api, created.id)
    assert e.value.code == ov.OvErrorCode.NOT_FOUND


async def test_event_stream_reports_a_vault_change(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    """Streaming: the core opens `GET {sync}/events` through the Python transport's open_stream and
    reads it with next_chunk while another device uploads."""
    email = f"events-{id(new_device)}@example.com"
    alice_dev = new_device()
    alice, kit = await register(alice_dev, email, "pw", relay)
    vault = await alice.create_vault("Infra", None)
    stream = await alice.subscribe()
    other = await login(new_device("other"), relay, email, "pw", kit.secret_key)
    theirs = await other.open_vault(vault.id())

    next_event = asyncio.ensure_future(stream.next())
    # Let the stream connect (the core opens it on the first poll), then upload from the other device.
    for _ in range(100):
        if any(u.endswith("/events") for u in alice_dev.http.urls):
            break
        await asyncio.sleep(0.02)
    await asyncio.sleep(0.2)
    theirs.add_entry(theirs.root_group_id(), entry_input({"Title": "New", "Password": "x"}))
    await theirs.sync(ov.SyncOptions(local_changed=True))

    ev = await asyncio.wait_for(next_event, timeout=15)
    while isinstance(ev, ov.AccountEvent.VAULTS_CHANGED):  # an access refresh can come first
        ev = await asyncio.wait_for(stream.next(), timeout=15)
    assert isinstance(ev, ov.AccountEvent.VAULT_CHANGED), ev
    assert ev.vault_id == vault.id()
    assert not ev.deleted
    assert ev.etag == theirs.etag()
    stream.close()
    assert await asyncio.wait_for(stream.next(), timeout=5) is None

"""The samples in docs/bindings/python.md, run against the testkit servers.

Each test follows one section of the page, with the same calls; only the issuer (the relay's
``https://auth.test``), the prompts (fixed strings) and the transport (behind ``RelayTransport``)
differ. Keep them in step with the page.

The page shows async calls without a ``CancelToken`` (``cancel=`` is optional). Until the binding
has that, these tests skip.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid

import openvireo as ov
import pytest
from openvireo import hosts

from test_smoke import KDF, offline_client

PASSWORD = "correct horse"


@pytest.fixture(autouse=True)
async def _needs_optional_cancel() -> None:
    try:
        await offline_client().discover("https://example.test")  # type: ignore[call-arg]
    except TypeError:
        pytest.skip("async calls still need a CancelToken argument (docs assume cancel= is optional)")
    except ov.OvError:
        pass


async def register(dev, relay, email: str) -> tuple[ov.Account, bytes]:  # type: ignore[no-untyped-def]
    a = await dev.client.connect(relay.issuer)
    kit = await a.register(ov.RegisterInput(email=email, password=PASSWORD.encode(), kdf=KDF, trust_device=True))
    return a, kit.secret_key


# "Sign in", with the prompts answered from a list.
async def sign_in(client: ov.OvClient, issuer: str, email: str, answers: list[str]) -> ov.Account:
    ask = answers.pop
    account = await client.connect(issuer)
    password = ask(0).encode()

    if account.is_signed_in():
        await account.unlock(password, None)
        return account

    login = ov.LoginInput(email=email, password=password, secret_key=None, totp=None, trust_device=True)
    try:
        step = await account.login(login)
    except ov.OvError as e:
        if e.code != ov.OvErrorCode.INVALID_SECRET_KEY:
            raise
        login.secret_key = ask(0).encode()
        step = await account.login(login)

    while isinstance(step, ov.LoginStep.NEEDS_TOTP):
        try:
            step = await account.submit_totp(step.challenge, ask(0))
        except ov.OvError as e:
            if e.code != ov.OvErrorCode.INVALID_MFA:
                raise
    return account


def device_with_store(relay, store: ov.SecureStore, tmp_path) -> ov.OvClient:  # type: ignore[no-untyped-def]
    from conftest import RelayTransport

    http = RelayTransport(hosts.UrllibTransport(timeout=10), relay.url)
    host = hosts.default_host(http=http, store=store, cache_dir=tmp_path)
    return ov.OvClient(
        ov.ClientConfig(device=ov.DeviceInfo(id=None, name="backup script", platform=ov.Platform.CLI),
                        offline=False, server=None),
        host,
    )


async def test_sign_in_and_stored_session(relay, new_device, tmp_path) -> None:  # type: ignore[no-untyped-def]
    email = f"docs-signin-{uuid.uuid4().hex}@example.com"
    _, secret_key = await register(new_device(), relay, email)

    # A new device: the first login has no Secret Key, the second one does.
    store = hosts.MemoryStore()
    client = device_with_store(relay, store, tmp_path)
    account = await sign_in(client, relay.issuer, email, [PASSWORD, secret_key.decode()])
    assert account.is_unlocked()

    # The next run on this device (same store): a stored session, unlocked with the password alone.
    client2 = device_with_store(relay, store, tmp_path)
    account2 = await sign_in(client2, relay.issuer, email, [PASSWORD])
    assert account2.is_unlocked()
    assert [v.name for v in await account2.vaults()] == []

    await account2.sign_out(False)
    assert not account2.is_signed_in()


async def test_sign_in_with_two_step(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    email = f"docs-totp-{uuid.uuid4().hex}@example.com"
    a, secret_key = await register(new_device(), relay, email)
    setup = await a.start_two_step()
    params = ov.parse_totp_uri(setup.uri)

    def code() -> str:
        return ov.totp_code(params, int(time.time() * 1000)).code.decode()

    await a.confirm_two_step(code())

    dev = new_device("second")
    # Wrong code first: invalid_mfa, and the same challenge takes the right one.
    account = await sign_in(dev.client, relay.issuer, email, [PASSWORD, secret_key.decode(), "000000", code()])
    assert account.is_unlocked()


async def test_vaults_entries_sync_share(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    email = f"docs-vaults-{uuid.uuid4().hex}@example.com"
    dev = new_device()
    account, _ = await register(dev, relay, email)
    await account.create_vault("Personal", None)

    # "Vaults and entries" + "Add an entry and sync"
    lines = []
    for info in await account.vaults():
        vault = await account.open_vault(info.id)
        entry_id = vault.add_entry(
            vault.ensure_group("Servers/Prod"),
            ov.EntryInput(
                fields=[
                    ov.FieldInput(name="Title", value=b"Router", protected=None),
                    ov.FieldInput(name="UserName", value=b"admin", protected=None),
                    ov.FieldInput(name="Password", value=b"correct horse", protected=None),
                ],
                remove_fields=[],
                tags=None,
                icon_id=None,
                expiry=ov.EntryExpiry.KEEP(),
            ),
        )
        report = await vault.sync(ov.SyncOptions(local_changed=True))
        assert report.outcome in (ov.SyncOutcome.UPLOADED, ov.SyncOutcome.CREATED)
        for entry in vault.entries(False):
            lines.append((info.name, "/".join(entry.group_path), entry.title, entry.username))
            rec = vault.entry(entry.id)
            password = next(f.value for f in rec.fields if f.name == "Password").decode()
            assert password == "correct horse"
    assert lines == [("Personal", "Servers/Prod", "Router", "admin")]
    assert vault.find("ov://Personal/Servers/Prod/Router").id == entry_id
    assert vault.read_field("ov://Personal/Servers/Prod/Router/Password") == b"correct horse"

    # "Share links"
    rec = vault.entry(entry_id)
    payload = ov.item_share_payload(rec, ov.default_share_fields(), None)
    created = await account.create_share(
        payload,
        ov.ShareOptions(expires_in=3600, max_opens=1, passcode=None, vault_id=vault.id(), entry_id=entry_id),
    )
    link = created.url.decode()
    assert "#" in link

    client = new_device("anon").client
    api = account.server_config().api
    share_id = ov.parse_share_link(link).id
    info = await client.share_info(api, share_id)
    opened = await client.open_share(api, link.encode(), None, info)
    shown = [(f.label, f.value.decode()) for f in opened.payload.fields]
    got = {f.k: f.value.decode() for f in opened.payload.fields}
    assert got == {"username": "admin", "password": "correct horse"}, shown
    assert [s.id for s in await account.list_shares()] == [created.id]
    await account.revoke_share(created.id)


async def test_errors(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    email = f"docs-errors-{uuid.uuid4().hex}@example.com"
    _, secret_key = await register(new_device(), relay, email)

    async def why(password: str, key: bytes) -> str:
        account = await new_device().client.connect(relay.issuer)
        login = ov.LoginInput(email=email, password=password.encode(), secret_key=key, totp=None, trust_device=True)
        try:
            await account.login(login)
        except ov.OvError as e:
            if e.code == ov.OvErrorCode.UNAUTHORIZED:
                reason = json.loads(e.details or "{}").get("reason")
                return "wrong Secret Key" if reason == "keyset_unwrap_failed" else "wrong email or password"
            raise
        return "ok"

    assert await why("nope", secret_key) == "wrong email or password"
    _, someone_elses_key = await register(new_device(), relay, f"other-{email}")
    assert await why(PASSWORD, someone_elses_key) == "wrong Secret Key"
    assert await why(PASSWORD, secret_key) == "ok"
    assert ov.error_code_wire(ov.OvErrorCode.PLAN_LIMIT) == "plan_limit"


async def test_cancellation(relay, new_device) -> None:  # type: ignore[no-untyped-def]
    account, _ = await register(new_device(), relay, f"docs-cancel-{uuid.uuid4().hex}@example.com")
    vault = await account.create_vault("V", None)

    token = ov.CancelToken()
    token.cancel()
    task = asyncio.create_task(vault.sync(ov.SyncOptions(local_changed=True), cancel=token))
    with pytest.raises(ov.OvError) as e:
        await task
    assert e.value.code == ov.OvErrorCode.ABORTED

    # Cancelling the task instead.
    task = asyncio.create_task(account.vaults())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_custom_transport_kdbx(relay, new_device, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    from conftest import RelayTransport

    class LoggedTransport(ov.HttpTransport):
        def __init__(self, inner: ov.HttpTransport) -> None:
            self.inner = inner

        async def send(self, req: ov.HttpRequest) -> ov.HttpResponse:
            res = await self.inner.send(req)
            print(req.method.name, req.url, res.status)
            return res

        async def open_stream(self, req: ov.HttpRequest) -> ov.OpenedStream:
            return await self.inner.open_stream(req)

    host = hosts.default_host(http=LoggedTransport(RelayTransport(hosts.UrllibTransport(), relay.url)))
    client = ov.OvClient(
        ov.ClientConfig(device=ov.DeviceInfo(id=None, name="t", platform=ov.Platform.CLI), offline=False, server=None),
        host,
    )
    await client.discover(relay.issuer)
    assert "GET https://auth.test/.well-known/openvireo-configuration 200" in capsys.readouterr().out

    # "Local .kdbx files"
    creds = ov.KdbxCredentials(password=b"pw", key_file=None)
    path = tmp_path / "db.kdbx"
    path.write_bytes(await (await client.create_local("Name", creds)).save_local())
    vault = await client.open_local(open(path, "rb").read(), creds)
    vault.add_entry(vault.root_group_id(), ov.EntryInput(
        fields=[ov.FieldInput(name="Title", value=b"x", protected=None)], remove_fields=[], tags=None,
        icon_id=None, expiry=ov.EntryExpiry.KEEP()))
    open(path, "wb").write(await vault.save_local())
    assert [e.title for e in (await client.open_local(path.read_bytes(), creds)).entries(False)] == ["x"]

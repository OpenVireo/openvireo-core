"""Type-checked, never run: ``tests/test_stubs.py`` runs mypy --strict and pyright on this file.

The good calls must pass. Each bad call carries an ignore comment for the error it must raise
(``# type: ignore[code]`` for mypy, ``# pyright: ignore[rule]`` for pyright); both checkers run with
unused ignores reported as errors, so a bad call that stopped being an error fails the test too.
"""

from __future__ import annotations

import openvireo as ov
from openvireo import CancelToken
from openvireo._core import ov_ffi


async def cancel_is_optional(client: ov.OvClient, account: ov.Account, stream: ov.EventStream) -> None:
    token = CancelToken()
    # Omitted, by keyword, positionally, and None either way.
    config: ov.ServerConfig = await client.discover("https://example.test")
    config = await client.discover("https://example.test", cancel=token)
    config = await client.discover("https://example.test", token)
    config = await client.discover("https://example.test", None)
    config = await client.discover(issuer="https://example.test", cancel=None)
    del config
    # Instance methods, classmethods, keyword arguments.
    vault: ov.Vault = await account.open_vault("vault-id")
    vault = await account.open_vault("vault-id", cancel=token)
    creds = ov.KdbxCredentials(password=b"pw", key_file=None)
    vault = await ov.Vault.create_local(name="Home", credentials=creds)
    vault = await ov.Vault.open_local(await vault.save_local(), creds, token)
    event: ov.AccountEvent | None = await stream.next()
    if isinstance(event, ov.AccountEvent.VAULT_CHANGED):
        vault_id: str = event.vault_id
        del vault_id
    # The generated module itself has the same signatures.
    await ov_ffi.OvClient.discover(client, "https://example.test")


async def bad_calls(client: ov.OvClient, account: ov.Account) -> None:
    await client.discover("https://example.test", cancel="token")  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
    await client.discover("https://example.test", 42)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
    await client.discover("https://example.test", CancelToken(), None)  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]
    await client.discover(cancel=CancelToken())  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]
    await account.open_vault("vault-id", canceled=CancelToken())  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]
    wrong: int = await client.discover("https://example.test")  # type: ignore[assignment]  # pyright: ignore[reportAssignmentType]
    del wrong


def records_enums_errors() -> None:
    expiry = ov.EntryExpiry.AT(1_700_000_000)
    at: int = expiry[0]
    keep: ov.EntryExpiry = ov.EntryExpiry.KEEP()
    del at, keep
    platform: ov.Platform = ov.Platform.CLI
    device = ov.DeviceInfo(id=None, name="sample", platform=platform)
    name: str = device.name
    del name
    try:
        ov.parse_secret_key("A3-…")
    except ov.OvError.Failure as failure:
        status: int | None = failure.status
        del status
    except ov.OvError as e:  # every OvError is a Failure, so the fields are on OvError too
        code: ov.OvErrorCode = e.code
        del code
    digest: bytes = ov.sha256(b"abc")
    del digest
    version: str = ov.__version__
    del version
    ov.DeviceInfo(id=None, name="sample")  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]
    ov.sha256("abc")  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]


class MyClock(ov.Clock):
    """A Host interface implemented in Python."""

    def now_unix_ms(self) -> int:
        return 0

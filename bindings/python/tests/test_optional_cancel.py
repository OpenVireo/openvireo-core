"""The optional ``cancel`` argument (``openvireo/_compat.py``): coverage of every generated call and
the three ways to call one (omitted, ``cancel=``, positional token)."""

from __future__ import annotations

import asyncio
import inspect
import typing

import openvireo as ov
import pytest
from openvireo import _compat, hosts
from openvireo._core import ov_ffi


def _takes_token(fn: typing.Callable[..., typing.Any]) -> bool:
    hints = typing.get_type_hints(fn, globalns=vars(ov_ffi))
    return any(h is ov.CancelToken for h in hints.values())


def _generated_with_token() -> list[tuple[str, typing.Callable[..., typing.Any]]]:
    """Every generated callable whose original signature has a CancelToken parameter (found by its
    annotation, independently of _compat), with the attribute as it's now looked up."""
    found = []
    for export in ov_ffi.__all__:
        obj = getattr(ov_ffi, export)
        if inspect.isclass(obj) and obj.__module__ == ov_ffi.__name__ and not obj.__dict__.get("_is_protocol"):
            for attr, raw in vars(obj).items():
                fn = getattr(raw, "__func__", raw)
                if inspect.isfunction(fn) and _takes_token(inspect.unwrap(fn)):
                    found.append((f"{export}.{attr}", getattr(obj, attr)))
        elif inspect.isfunction(obj) and _takes_token(inspect.unwrap(obj)):
            found.append((export, getattr(ov, export)))
    return found


GENERATED = _generated_with_token()


def test_the_wrapper_found_everything() -> None:
    assert len(GENERATED) > 100  # Account alone has ~80
    assert sorted(name for name, _ in GENERATED) == sorted(ov._CANCEL_OPTIONAL)


@pytest.mark.parametrize(("name", "fn"), GENERATED, ids=[n for n, _ in GENERATED])
def test_every_call_takes_an_optional_cancel(name: str, fn: typing.Callable[..., typing.Any]) -> None:
    assert getattr(fn, _compat.MARKER, False), name
    original = inspect.unwrap(fn)
    assert fn.__name__ == original.__name__ and fn.__doc__ == original.__doc__
    assert inspect.iscoroutinefunction(fn) == inspect.iscoroutinefunction(original)
    params = list(inspect.signature(fn).parameters.values())
    cancel = inspect.signature(fn).parameters["cancel"]
    assert cancel.default is None
    assert cancel.annotation == "CancelToken | None"
    assert params[-1] is cancel  # same position as the generated token
    # A call without the token binds; so do the keyword and positional forms.
    required = [p for p in params if p.default is inspect.Parameter.empty]
    dummies = [object()] * len(required)
    inspect.signature(fn).bind(*dummies)
    inspect.signature(fn).bind(*dummies, cancel=ov.CancelToken())
    inspect.signature(fn).bind(*dummies, ov.CancelToken())


def test_the_public_names_are_the_wrapped_ones() -> None:
    assert ov.OvClient.discover is ov_ffi.OvClient.discover
    assert getattr(ov.Vault.open_local, _compat.MARKER)  # classmethod
    assert getattr(ov.EventStream.next, _compat.MARKER)


def test_applying_it_twice_is_a_no_op() -> None:
    assert _compat.make_cancel_optional(ov_ffi, ov.CancelToken) == []


# ------------------------------------------------------------------ calling


class OfflineHttp(ov.HttpTransport):
    async def send(self, req: ov.HttpRequest) -> ov.HttpResponse:
        raise ov.TransportError.Offline()

    async def open_stream(self, req: ov.HttpRequest) -> ov.OpenedStream:
        raise ov.TransportError.Offline()


class HangingHttp(ov.HttpTransport):
    """Never answers; records that the core dropped (cancelled) the request."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def send(self, req: ov.HttpRequest) -> ov.HttpResponse:
        self.started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        raise AssertionError("unreachable")

    async def open_stream(self, req: ov.HttpRequest) -> ov.OpenedStream:
        return await asyncio.Future()


def client(http: ov.HttpTransport | None = None) -> ov.OvClient:
    config = ov.ClientConfig(
        device=ov.DeviceInfo(id=None, name="cancel", platform=ov.Platform.CLI), offline=False, server=None
    )
    return ov.OvClient(config, hosts.default_host(http=http or OfflineHttp()))


def cancelled() -> ov.CancelToken:
    t = ov.CancelToken()
    t.cancel()
    return t


async def code_of(call: typing.Awaitable[typing.Any]) -> ov.OvErrorCode:
    with pytest.raises(ov.OvError) as e:
        await call
    return e.value.code


async def test_omitted_runs_the_call() -> None:
    assert await code_of(client().discover("https://example.test")) == ov.OvErrorCode.NETWORK_ERROR


async def test_none_runs_the_call() -> None:
    assert await code_of(client().discover("https://example.test", None)) == ov.OvErrorCode.NETWORK_ERROR
    assert await code_of(client().discover("https://example.test", cancel=None)) == ov.OvErrorCode.NETWORK_ERROR


async def test_keyword_token_aborts() -> None:
    assert await code_of(client().discover("https://example.test", cancel=cancelled())) == ov.OvErrorCode.ABORTED


async def test_positional_token_aborts() -> None:
    assert await code_of(client().discover("https://example.test", cancelled())) == ov.OvErrorCode.ABORTED


async def test_keyword_arguments_and_classmethods() -> None:
    creds = ov.KdbxCredentials(password=b"pw", key_file=None)
    v = await ov.Vault.create_local(name="Home", credentials=creds)
    data = await v.save_local()
    assert (await ov.Vault.open_local(data, creds)).root_group_id() == v.root_group_id()
    assert await code_of(ov.Vault.open_local(data, creds, cancel=cancelled())) == ov.OvErrorCode.ABORTED


async def test_cancelling_a_token_mid_call_aborts() -> None:
    http = HangingHttp()
    token = ov.CancelToken()
    call = asyncio.ensure_future(client(http).discover("https://example.test", cancel=token))
    await asyncio.wait_for(http.started.wait(), 5)
    token.cancel()
    assert await asyncio.wait_for(code_of(call), 5) == ov.OvErrorCode.ABORTED


async def test_cancelling_the_task_drops_the_call() -> None:
    http = HangingHttp()
    call = asyncio.ensure_future(client(http).discover("https://example.test"))
    await asyncio.wait_for(http.started.wait(), 5)
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    await asyncio.wait_for(http.cancelled.wait(), 5)


async def test_each_call_gets_its_own_token(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[ov.CancelToken] = []
    original = inspect.unwrap(ov.OvClient.discover)

    async def spy(self: ov.OvClient, issuer: str, cancel: ov.CancelToken) -> typing.Any:
        seen.append(cancel)
        return await original(self, issuer, cancel)

    wrapped = _compat._wrap(spy, ov.CancelToken, globals())
    assert wrapped is not None
    monkeypatch.setattr(ov.OvClient, "discover", wrapped)
    c = client()
    for _ in range(2):
        await code_of(c.discover("https://example.test"))
    assert len(seen) == 2 and seen[0] is not seen[1]
    assert all(isinstance(t, ov.CancelToken) and not t.is_cancelled() for t in seen)

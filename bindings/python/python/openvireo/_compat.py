"""Makes the ``CancelToken`` argument optional on every generated call.

UniFFI can't give an object argument a default, so every async method of the generated module
(``openvireo._core``) takes a required ``CancelToken``. At import time this module rewraps each
generated function or method that has a parameter annotated ``CancelToken`` so that the parameter
becomes ``cancel: CancelToken | None = None``; when it's omitted (or ``None``), a fresh
``CancelToken()`` is passed. The parameter keeps its position (it's always the last one), so
passing a token positionally still works, and so does ``cancel=token``.

The wrappers are found by type annotation, not by hand: a new core method gets the same treatment
without touching this file. ``tests/test_optional_cancel.py`` checks that nothing was missed.

Cancelling the asyncio task that awaits a call still drops the Rust future (the wrapper only awaits
the generated coroutine); a token that's passed and cancelled still ends the call with ``ABORTED``.
"""

from __future__ import annotations

import functools
import inspect
import types
import typing
from collections.abc import Callable, Coroutine
from typing import Any

#: The public keyword for the token on every wrapped call.
CANCEL = "cancel"

#: Set on every wrapper this module makes (so applying it twice is a no-op, and tests can find them).
MARKER = "__ov_optional_cancel__"

_Fn = Callable[..., Any]


def _cancel_param(fn: _Fn, token_type: type, namespace: dict[str, Any]) -> inspect.Parameter | None:
    """The parameter of ``fn`` typed ``CancelToken``, if any. The generated module uses
    ``from __future__ import annotations``, so annotations are strings resolved against it."""
    try:
        hints = typing.get_type_hints(fn, globalns=namespace)
    except Exception:  # an annotation that doesn't resolve: fall back to the raw strings
        hints = {}
    for p in inspect.signature(fn).parameters.values():
        hint = hints.get(p.name, p.annotation)
        if hint is token_type or hint == token_type.__name__:
            return p
    return None


def _wrap(fn: _Fn, token_type: type, namespace: dict[str, Any]) -> _Fn | None:
    """``fn`` with its ``CancelToken`` parameter optional, or ``None`` when it has none."""
    if getattr(fn, MARKER, False):
        return None
    param = _cancel_param(fn, token_type, namespace)
    if param is None:
        return None
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    index = params.index(param)
    if any(p.default is inspect.Parameter.empty for p in params[index + 1 :]):
        raise TypeError(f"{fn.__qualname__}: required parameters after `{param.name}`; can't default it")
    name = param.name

    def fill(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[tuple[Any, ...], dict[str, Any]]:
        if name != CANCEL and CANCEL in kwargs:
            kwargs[name] = kwargs.pop(CANCEL)
        if len(args) > index:
            if args[index] is None:
                args = (*args[:index], token_type(), *args[index + 1 :])
        elif kwargs.get(name) is None:
            kwargs[name] = token_type()
        return args, kwargs

    wrapper: _Fn
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            args, kwargs = fill(args, kwargs)
            coro: Coroutine[Any, Any, Any] = fn(*args, **kwargs)
            return await coro

        wrapper = async_wrapper
    else:

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            args, kwargs = fill(args, kwargs)
            return fn(*args, **kwargs)

        wrapper = sync_wrapper

    new = param.replace(name=CANCEL, default=None, annotation=f"{token_type.__name__} | None")
    params[index] = new
    setattr(wrapper, "__signature__", sig.replace(parameters=params))  # noqa: B010
    annotations = dict(getattr(fn, "__annotations__", {}))
    annotations.pop(name, None)
    annotations[CANCEL] = new.annotation
    wrapper.__annotations__ = annotations
    setattr(wrapper, MARKER, True)
    return wrapper


def _is_protocol(cls: type) -> bool:
    return bool(cls.__dict__.get("_is_protocol", False))


def make_cancel_optional(module: types.ModuleType, token_type: type) -> list[str]:
    """Rewraps, in place, every function of ``module.__all__`` and every method of its classes
    (not the ``typing.Protocol`` ones, which only describe them) that takes a ``token_type``.
    Returns the qualified names wrapped."""
    namespace = vars(module)
    done: list[str] = []
    for export in getattr(module, "__all__", []):
        obj = getattr(module, export)
        if inspect.isclass(obj):
            if obj.__module__ != module.__name__ or _is_protocol(obj):
                continue
            for attr, raw in list(vars(obj).items()):
                if isinstance(raw, (classmethod, staticmethod)):
                    inner = raw.__func__
                    if inspect.isfunction(inner) and (w := _wrap(inner, token_type, namespace)):
                        setattr(obj, attr, type(raw)(w))
                        done.append(f"{export}.{attr}")
                elif inspect.isfunction(raw) and (w := _wrap(raw, token_type, namespace)):
                    setattr(obj, attr, w)
                    done.append(f"{export}.{attr}")
        elif inspect.isfunction(obj) and (w := _wrap(obj, token_type, namespace)):
            setattr(module, export, w)
            done.append(export)
    return done

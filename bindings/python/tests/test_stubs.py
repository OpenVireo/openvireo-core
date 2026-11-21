"""The type stubs (``openvireo/__init__.pyi``, ``openvireo/_core/ov_ffi.pyi``, written by
``scripts/gen_stubs.py``): current, consistent with the runtime module and ``_compat``, and what type
checkers actually see (mypy --strict and pyright on ``typecheck_sample.py``)."""

from __future__ import annotations

import ast
import inspect
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import openvireo as ov
import pytest
from openvireo._core import ov_ffi

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(PROJECT / "scripts"))
import gen_stubs  # noqa: E402

SAMPLE = HERE / "typecheck_sample.py"
#: Pinned so CI doesn't change verdicts under us.
PYRIGHT = "pyright@1.1.414"


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), str(path))


CORE = parse(gen_stubs.CORE_STUB)
INIT = parse(gen_stubs.INIT_STUB)


def dunder_all(tree: ast.Module) -> list[str]:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            value = ast.literal_eval(node.value)
            assert isinstance(value, list)
            return [str(v) for v in value]
    raise AssertionError("no __all__")


def top_level(tree: ast.Module) -> dict[str, ast.stmt]:
    out: dict[str, ast.stmt] = {}
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = node
    return out


def find(qualname: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """A function (``name``) or method (``Class.name``) of the core stub."""
    scope: list[ast.stmt] = CORE.body
    *outer, name = qualname.split(".")
    for part in outer:
        scope = next(n for n in scope if isinstance(n, ast.ClassDef) and n.name == part).body
    return next(n for n in scope if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)


def has_test_server() -> bool:
    return bool(ov_ffi.opaque_has_test_server())


# ------------------------------------------------------------------ consistency


def test_the_stubs_are_current() -> None:
    for path, text in gen_stubs.generate().items():
        assert path.read_text() == text, f"{path} is stale: run `cargo xtask python --stubs`"


def test_the_stub_names_are_the_runtime_names() -> None:
    runtime = list(ov_ffi.__all__)
    release = gen_stubs.release_names(ov_ffi)
    assert dunder_all(CORE) == release
    assert set(top_level(CORE)) == {*release, "uniffi_set_event_loop"}
    # Only a test-server build has more, and only the opaque_server_* steps.
    extra = set(runtime) - set(release)
    assert bool(extra) == has_test_server()
    assert all(gen_stubs.TEST_SERVER_ONLY.match(n) for n in extra)
    # The package re-exports the same names it does at runtime.
    assert set(dunder_all(INIT)) == set(ov.__all__) - extra
    for name in dunder_all(INIT):
        assert hasattr(ov, name), name


def test_every_cancel_optional_call_has_the_optional_param() -> None:
    assert len(ov._CANCEL_OPTIONAL) > 100
    for qualname in ov._CANCEL_OPTIONAL:
        node = find(qualname)
        fn = _attr(qualname)
        runtime = inspect.signature(fn)
        positional = [*node.args.posonlyargs, *node.args.args]
        # Same position and kind as at runtime: the last positional parameter, default None.
        assert positional[-1].arg == "cancel", qualname
        assert not node.args.kwonlyargs and node.args.vararg is None, qualname
        assert ast.unparse(positional[-1].annotation or ast.Constant(None)) == "CancelToken | None", qualname
        assert node.args.defaults and isinstance(node.args.defaults[-1], ast.Constant), qualname
        assert node.args.defaults[-1].value is None, qualname
        assert [a.arg for a in positional] == list(runtime.parameters), qualname
        assert isinstance(node, ast.AsyncFunctionDef) == inspect.iscoroutinefunction(fn), qualname


def _attr(qualname: str) -> Callable[..., Any]:
    """The runtime callable, unbound (a classmethod's function, with ``cls``)."""
    obj: Any = ov_ffi
    for part in qualname.split("."):
        obj = inspect.getattr_static(obj, part)
    fn: Callable[..., Any] = getattr(obj, "__func__", obj)
    assert callable(fn)
    return fn


def test_no_other_call_needs_a_token() -> None:
    """Outside the Protocol classes (which mirror the generated ones), no stub signature has a
    required CancelToken, and every ``cancel: CancelToken | None`` is a _compat one."""
    wrapped = set(ov._CANCEL_OPTIONAL)
    for node in CORE.body:
        if isinstance(node, ast.ClassDef):
            if any(ast.unparse(b) == "typing.Protocol" for b in node.bases):
                continue
            fns = [
                (f"{node.name}.{f.name}", f)
                for f in node.body
                if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fns = [(node.name, node)]
        else:
            continue
        for qualname, fn in fns:
            anns = [ast.unparse(a.annotation) for a in [*fn.args.args, *fn.args.kwonlyargs] if a.annotation]
            assert "CancelToken" not in anns, qualname
            assert ("CancelToken | None" in anns) == (qualname in wrapped), qualname


# ------------------------------------------------------------------ type checkers


def test_mypy_strict_accepts_the_package_and_the_sample(tmp_path: Path) -> None:
    pytest.importorskip("mypy")
    for target in (["python/openvireo/__init__.py"], [str(SAMPLE)], []):  # [] = the [tool.mypy] files
        result = subprocess.run(
            [sys.executable, "-m", "mypy", "--strict", "--warn-unused-ignores", "--cache-dir", str(tmp_path), *target],
            cwd=PROJECT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr


def test_mypy_rejects_what_the_sample_marks(tmp_path: Path) -> None:
    """The ignores in the sample are load-bearing: without them each marked line is an error."""
    pytest.importorskip("mypy")
    stripped = tmp_path / "sample_without_ignores.py"
    lines = SAMPLE.read_text().splitlines()
    marked = [i for i, line in enumerate(lines, 1) if "  # type: ignore[" in line]
    stripped.write_text("\n".join(line.split("  # type: ignore")[0] for line in lines) + "\n")
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", "--cache-dir", str(tmp_path / "cache"), str(stripped)],
        cwd=PROJECT,
        capture_output=True,
        text=True,
    )
    flagged = {int(line.split(":")[1]) for line in result.stdout.splitlines() if ": error:" in line}
    assert len(marked) >= 8
    assert flagged == set(marked), result.stdout


def test_pyright_strict_accepts_the_sample(tmp_path: Path) -> None:
    uvx = shutil.which("uvx")
    if uvx is None:
        pytest.skip("uvx isn't on PATH (pyright runs through it)")
    config = tmp_path / "pyrightconfig.json"
    config.write_text(
        json.dumps(
            {
                "pythonVersion": "3.10",
                "typeCheckingMode": "strict",
                # Only `# pyright: ignore[...]` counts, and an unneeded one is an error.
                "enableTypeIgnoreComments": False,
                "reportUnnecessaryTypeIgnoreComment": "error",
            }
        )
    )
    result = subprocess.run(
        [uvx, PYRIGHT, "--pythonpath", sys.executable, "-p", str(config), str(SAMPLE)],
        cwd=PROJECT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 errors" in result.stdout, result.stdout

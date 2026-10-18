from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest

from entra_mcp_server import bootstrap


def test_ensure_dependencies_skips_install_when_all_modules_are_available(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        bootstrap,
        "_check_runtime_imports",
        lambda: subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        bootstrap.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("pip should not run")),
    )

    bootstrap.ensure_dependencies()


def test_ensure_dependencies_installs_project_if_modules_are_missing(monkeypatch) -> None:
    pip_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    checks = iter(
        (
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="ModuleNotFoundError: msal"
            ),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        )
    )

    def run(*args: object, **kwargs: object) -> None:
        pip_calls.append((args, kwargs))

    monkeypatch.setattr(bootstrap, "_check_runtime_imports", lambda: next(checks))
    monkeypatch.setattr(bootstrap.subprocess, "run", run)
    monkeypatch.setattr(bootstrap, "PROJECT_ROOT", Path("project"))

    bootstrap.ensure_dependencies()

    assert len(pip_calls) == 1
    args, kwargs = pip_calls[0]
    assert args[0] == [
        sys.executable,
        "-m",
        "pip",
        "install",
        "-e",
        "project",
    ]
    assert kwargs == {"cwd": Path("project"), "check": True}


def test_ensure_dependencies_reports_import_failure_after_install(monkeypatch) -> None:
    checks = iter(
        (
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="ModuleNotFoundError: pywintypes"
            ),
            subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="ModuleNotFoundError: pywintypes"
            ),
        )
    )
    monkeypatch.setattr(bootstrap, "_check_runtime_imports", lambda: next(checks))
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda *args, **kwargs: None)

    with pytest.raises(RuntimeError, match="pywintypes"):
        bootstrap.ensure_dependencies()


def test_load_environment_uses_project_dotenv_without_overriding_process_env(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[tuple[Path, bool]] = []
    dotenv = ModuleType("dotenv")
    dotenv.load_dotenv = lambda path, override: calls.append((path, override))
    monkeypatch.setitem(sys.modules, "dotenv", dotenv)
    monkeypatch.setattr(bootstrap, "PROJECT_ROOT", tmp_path)
    (tmp_path / ".env").write_text("EXAMPLE=value", encoding="utf-8")

    bootstrap.load_environment()

    assert calls == [(tmp_path / ".env", False)]

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_IMPORT_CHECK = """
import httpx
import mcp
from mcp.server import MCPServer
import msal
import jwt
import cryptography
import pydantic
import dotenv
import starlette
import uvicorn
if sys.platform == "win32":
    import pywintypes
"""


def _check_runtime_imports() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", "import sys; " + RUNTIME_IMPORT_CHECK],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def ensure_dependencies() -> None:
    check = _check_runtime_imports()
    if check.returncode == 0:
        print("Runtime dependencies are available.")
        return

    print("Runtime dependency import check failed; installing the project dependencies.")
    if check.stderr.strip():
        print(check.stderr.rstrip(), file=sys.stderr)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", str(PROJECT_ROOT)],
        cwd=PROJECT_ROOT,
        check=True,
    )

    check = _check_runtime_imports()
    if check.returncode != 0:
        details = check.stderr.strip() or check.stdout.strip() or "No import error details were returned."
        raise RuntimeError(f"Dependencies are still unusable after installation:\n{details}")


def load_environment() -> None:
    from dotenv import load_dotenv

    env_path = PROJECT_ROOT / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)
        print(f"Loaded configuration from {env_path.name}.")
    else:
        print(
            f"No {env_path.name} file found; using environment variables.",
            file=sys.stderr,
        )

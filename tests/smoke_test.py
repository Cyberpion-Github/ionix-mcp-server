"""Isolated startup smoke test for the IONIX MCP server.

Launches the real ``ionix-mcp`` console-script server over stdio (the exact
entry point a customer uses), performs an MCP ``initialize`` + ``tools/list``
handshake with the official MCP client SDK, and asserts the server starts and
serves its tools.

This catches the class of failure fixed in PR #2: a bad dependency resolution
that let the server crash on startup. Because CI runs this via ``uv run`` in a
freshly resolved environment, it reproduces the customer install path rather
than relying on an already-good local venv.

Run locally:  uv run --refresh python tests/smoke_test.py
Exits 0 and prints ``OK: N tools`` on success; non-zero on any failure.
"""

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Stable, core tools that are very unlikely to be renamed/removed. Presence of
# these guards against a partial or regressed tool registration without pinning
# an exact count (the tool set legitimately grows over time).
REQUIRED_TOOLS = {"get_discovery_org_assets", "get_action_items_open"}

# Auth is never exercised: the server registers tools at startup, long before
# any API call, so dummy credentials keep the test hermetic and fork-safe.
DUMMY_ENV = {"IONIX_API_KEY": "dummy", "IONIX_ACCOUNT_NAME": "dummy"}

STARTUP_TIMEOUT_SECONDS = 30


async def _run() -> int:
    params = StdioServerParameters(
        command="ionix-mcp",
        env={**os.environ, **DUMMY_ENV},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert (
                init.serverInfo.name == "ionix"
            ), f"unexpected serverInfo: {init.serverInfo!r}"

            tools = (await session.list_tools()).tools
            names = {tool.name for tool in tools}
            assert tools, "server returned zero tools"

            missing = REQUIRED_TOOLS - names
            assert not missing, f"missing core tools: {sorted(missing)}"

            print(f"OK: {len(tools)} tools")
            return len(tools)


def main() -> None:
    try:
        asyncio.run(asyncio.wait_for(_run(), STARTUP_TIMEOUT_SECONDS))
    except asyncio.TimeoutError:
        sys.exit(
            f"FAIL: server did not complete the MCP handshake within "
            f"{STARTUP_TIMEOUT_SECONDS}s (startup hang?)"
        )
    except AssertionError as exc:
        sys.exit(f"FAIL: {exc}")
    except Exception as exc:  # server crashed on startup, import error, etc.
        sys.exit(f"FAIL: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()

"""Fixed fixture for MC002 -- the LiteLLM 7b7f304 patch shape.

``MCP_STDIO_ALLOWED_COMMANDS`` is a module-level ``frozenset`` of known MCP
launchers; ``build_server`` checks ``os.path.basename(command) not in ALLOWED``
before constructing ``StdioServerParameters``. This is the exact fix that landed
in LiteLLM v1.83.6-nightly / v1.83.7-stable. The rule must stay silent here.
"""

import os

from mcp.client.stdio import StdioServerParameters

MCP_STDIO_ALLOWED_COMMANDS = frozenset(
    {"npx", "uvx", "python", "python3", "node", "docker", "deno"}
)


def build_server(user_config):
    command = user_config["command"]
    args = list(user_config.get("args", []))
    if os.path.basename(command) not in MCP_STDIO_ALLOWED_COMMANDS:
        raise ValueError(f"command {command!r} not in stdio allowlist")
    return StdioServerParameters(command=command, args=args, env=None)

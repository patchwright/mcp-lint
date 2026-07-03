"""Fixed fixture for MC002 -- inline allowlist (no module-level constant).

An operator who cannot edit module-level state can still guard inline. The rule
recognises ``x not in {"npx", ...}`` (string-set literal) as a guard and stays
silent. Mirrors the Upsonic/Flowise hardening pattern from the OX advisory
(Family #2), minus their argument-bypass bug (a separate class).
"""

from mcp.client.stdio import StdioServerParameters


def build_server(user_config):
    command = user_config["command"]
    args = list(user_config.get("args", []))
    if command not in {"npx", "uvx", "python", "python3", "node"}:
        raise ValueError("not allowed")
    return StdioServerParameters(command=command, args=args)

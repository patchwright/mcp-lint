"""Vulnerable fixture for MC002 -- the documented shape of CVE-2026-30623.

Mirrors the LiteLLM pre-7b7f304 code path: a user-supplied JSON config feeds
``command``/``args`` straight into ``StdioServerParameters`` with no allowlist.
An authenticated user could put any binary in ``command`` and the proxy host
ran it. OX Security's advisory shows the same shape in LangFlow, GPT Researcher,
Agent Zero, LangBot, Bisheng, Jaaz, Langchain-Chatchat, Fay.
"""

from mcp.client.stdio import StdioServerParameters


def build_server(user_config):
    # user_config comes from an authenticated POST body; command is attacker-
    # controlled and reaches the SDK sink with no validation.
    command = user_config["command"]
    args = list(user_config.get("args", []))
    return StdioServerParameters(command=command, args=args, env=None)

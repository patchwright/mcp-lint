"""Safe fixture for MC002 -- literal command, statically known.

A string-literal ``command`` cannot be attacker-controlled at construction time,
so the rule stays silent (it is the documented SDK-launcher pattern, e.g. a
hardcoded ``npx`` launcher). Covers positional and keyword argument forms.
"""

from mcp.client.stdio import StdioServerParameters


def hardcoded_keyword():
    return StdioServerParameters(command="npx", args=["-y", "@modelcontextprotocol/server-everything"])


def hardcoded_positional():
    # `command` is the first field of the SDK dataclass -> positional [0].
    return StdioServerParameters("uvx", args=["mcp-server-fetch"])


def hardcoded_fstring_no_interpolation():
    # f-string with NO interpolation is statically known -> treated as literal.
    return StdioServerParameters(command=f"python3")

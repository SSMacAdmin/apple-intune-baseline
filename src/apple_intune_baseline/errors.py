"""Errors meant for the person, not crashes.

MCP SDK 2.x hides the text of unexpected exceptions from the model, so input
problems (unknown baseline, unsupported platform) must be raised as
``ToolError`` to come through with their helpful message.
"""

from mcp.server.mcpserver.exceptions import ToolError


class UserInputError(ToolError, ValueError):
    """Bad input the person can fix, e.g. a misspelled baseline or platform."""

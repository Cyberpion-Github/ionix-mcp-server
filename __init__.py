"""
IONIX MCP Server

A Model Context Protocol (MCP) server that provides comprehensive tools
for interacting with the IONIX API.
"""

__version__ = "1.0.0"
__author__ = "IONIX"

from .ionix import mcp

def main():
    """Main entry point for the IONIX MCP server."""
    mcp.run()

__all__ = ["main", "mcp"]
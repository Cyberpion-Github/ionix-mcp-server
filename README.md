# IONIX MCP Server

A Model Context Protocol (MCP) server that provides comprehensive tools for interacting with the IONIX API. This server enables Claude Desktop and other MCP clients to query asset information, security assessments, remediation items, and more from your IONIX account.

## Usage

1. Install uv if you haven't already:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

2. If you hadn't done so already, configure Bitbucket access by adding your machine's SSH key here: https://bitbucket.org/account/settings/ssh-keys/

3. Update the Claude Desktop configuration file to include the MCP server:
```json
{
  "mcpServers": {
    "ionix": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/Cyberpion-Github/ionix-mcp-server.git@main",
        "ionix-mcp"
      ],
      "env": {
          "IONIX_API_KEY": "Your IONIX API key"
      }
    }
  }
}
```

Place your IONIX API key in the `IONIX_API_KEY` environment variable. You can generate an API key in the IONIX platform under Settings -> API -> Create Token.

The Claude Desktop config file is in `~/Library/Application Support/Claude/claude_desktop_config.json` on Mac and in `%APPDATA%\Claude\claude_desktop_config.json` on Windows.

Note: you can also add an `IONIX_ACCOUNT_NAME` environment variable if you want to set a default account to be used in all API calls.

4. Restart Claude Desktop

### Example Queries

You can ask Claude to:

**Basic Asset Discovery:**
- "Get all organization assets containing 'example.com'"
- "Show me the technologies discovered on assets"
- "What are the open action items for remediation?"

**Enhanced Asset Discovery (NEW!):**
- "Find assets with HTTPS titles containing 'Admin Panel'"
- "Show me assets hosted on AWS in the US region"
- "Get assets with CVE vulnerabilities containing 'CVE-2023'"
- "Find domains expiring before 2024-12-31"
- "Show me assets with HTTP status code 200 that are web accessible"
- "Find assets with open ports 80,443 on specific hosting providers"

**Risk & Security Analysis:**
- "Get the attack surface risk score details"
- "Show me certificates for assets containing 'mycompany'"
- "Get all action items for the asset api.example.com"

### Multi-Account Support

All tools support an optional `account_name` parameter for querying different IONIX accounts:


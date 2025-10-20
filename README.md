# IONIX MCP Server (Beta)

A Model Context Protocol (MCP) server that provides comprehensive tools for interacting with the IONIX API. This server enables Claude Desktop and other MCP clients to query asset information, security findings (action items), security assessments, remediation items, and more from your IONIX account.

Note: the IONIX MCP server is in beta.

## Usage

1. Install uv if you haven't already ([installation guide for your OS](https://docs.astral.sh/uv/getting-started/installation/)):
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

2. Update the Claude Desktop configuration file to include the MCP server:
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
          "IONIX_API_KEY": "Your IONIX API key",
          "IONIX_ACCOUNT_NAME": "Your IONIX account name"
      }
    }
  }
}
```

Place your IONIX API key in the `IONIX_API_KEY` environment variable. You can generate an API key in the IONIX platform under Settings -> API -> Create Token.

The Claude Desktop config file is in `~/Library/Application Support/Claude/claude_desktop_config.json` on Mac and in `%APPDATA%\Claude\claude_desktop_config.json` on Windows.

Place your account name in the `IONIX_ACCOUNT_NAME` environment variable. Reach out to IONIX support if you need help finding your account name.

3. Restart Claude Desktop - you should see the IONIX MCP servers listed as an available "connector". 

Note: make sure `uvx` is in your system PATH. If it is not, you can try replacing `"command": "uvx"` with the full path to the `uvx` executable, e.g. `/Users/YOUR_USERNAME/.local/bin/uvx`.

### Example Queries

You can ask Claude to:

**Basic Asset Discovery:**
- "Get all organization assets containing 'example.com'"
- "Show me the technologies discovered on assets"
- "What are the open action items for remediation?"

**Enhanced Asset Discovery:**
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

**MSSP Management:**
- "Get MSSP company info"
- "List MSSP sub-accounts with name containing 'Acme'"
- "Get MSSP sub-account details for company 'AcmeCo'"

### Multi-Account Support

All tools support an optional `account_name` parameter for querying different IONIX accounts (for MSSPs).

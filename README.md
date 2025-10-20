# IONIX MCP Server (Beta)

A Model Context Protocol (MCP) server that provides comprehensive tools for interacting with the IONIX API. This server enables Claude Desktop and other MCP clients to query asset information, security findings (action items), security assessments, remediation items, and more from your IONIX account.

Note: the IONIX MCP server is in beta.

## Usage

1. Install uv if you haven't already ([installation guide for your OS](https://docs.astral.sh/uv/getting-started/installation/)):
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

2. Locate or create the Claude Desktop configuration file. The location depends on your operating system:
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

   If the file doesn't exist, create it. If it already exists, you'll add the IONIX configuration to the existing `mcpServers` section.

3. Determine your uvx path. Use the full path to `uvx` based on your operating system (replace `YOUR_USERNAME` with your actual username):
   - **macOS/Linux:** `/Users/YOUR_USERNAME/.local/bin/uvx`
   - **Windows:** `C:\Users\YOUR_USERNAME\.local\bin\uvx.exe`

4. Get your IONIX credentials:
   - **API Key:** Generate an API key in the IONIX platform under Settings -> API -> Create Token
   - **Account Name:** Your IONIX account name (reach out to IONIX support if you need help finding it)

5. Edit the configuration file:

   **If the file is new or empty**, paste this entire configuration (remember to replace `YOUR_USERNAME`, `Your IONIX API key`, and `Your IONIX account name`):

   ```json
   {
     "mcpServers": {
       "ionix": {
         "command": "/Users/YOUR_USERNAME/.local/bin/uvx",
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

   **If the file already has other MCP servers configured**, add the `ionix` section inside the existing `mcpServers` object. For example:

   ```json
   {
     "mcpServers": {
       "existing-server": {
         "command": "...",
         "args": ["..."]
       },
       "ionix": {
         "command": "/Users/YOUR_USERNAME/.local/bin/uvx",
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

6. Restart Claude Desktop - you should see the IONIX MCP servers listed as an available "connector".

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

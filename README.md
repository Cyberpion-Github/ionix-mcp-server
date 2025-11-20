# IONIX MCP Server (Beta)

A Model Context Protocol (MCP) server that provides comprehensive tools for interacting with the IONIX API. This server enables Claude Desktop and other MCP clients to query asset information, security findings (action items), security assessments, remediation items, and more from your IONIX account.

Note: the IONIX MCP server is in beta.

## Prerequisites

Before installing the IONIX MCP server, ensure you have the following:

1. **Claude Desktop** - Download and install from [claude.ai/download](https://claude.ai/download)

2. **Git** - Required for installing the MCP server from the repository:
   - **macOS:** Install via [Homebrew](https://brew.sh/) (`brew install git`) or download from [git-scm.com](https://git-scm.com/download/mac)
   - **Windows:** Download and install from [git-scm.com](https://git-scm.com/download/win)

## Usage

1. Install uv if you haven't already ([installation guide for your OS](https://docs.astral.sh/uv/getting-started/installation/)):
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

2. Locate or create the Claude Desktop configuration file:

   **Option 1 - Via Claude Desktop Settings:**
   - Open Claude Desktop
   - Go to Settings (gear icon)
   - Navigate to Developer section
   - Click "Edit Config" to open the configuration file

   **Option 2 - Manual file location** (varies by operating system):
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

   If the file doesn't exist, create it. If it already exists, you'll add the IONIX configuration to the existing `mcpServers` section.

3. Determine your uvx path. Use the full path to `uvx` based on your operating system (replace `YOUR_USERNAME` with your actual username):
   - **macOS/Linux:** `/Users/YOUR_USERNAME/.local/bin/uvx`
   - **Windows:** `C:\Users\YOUR_USERNAME\.local\bin\uvx.exe`

4. Get your IONIX credentials:
   - **API Key:** Generate an API key in the IONIX platform under Settings -> API -> Create Token
     - **Important:** Pay attention to the expiry date when creating the API key. After the expiry date, the IONIX MCP server will stop working until you generate a new API key and update your configuration
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

6. Restart Claude Desktop and verify the installation:
   - After restarting, open Claude Desktop Settings
   - Navigate to Developer section
   - Look for "ionix" in the MCP Servers list
   - Verify the status shows as "running"
   - If it shows an error, check your configuration file for typos or incorrect paths

## Privacy & Security Recommendations

**Important:** When using the IONIX MCP server with AI tools like Claude Desktop, we strongly recommend disabling data collection and training features to protect your sensitive security data:

### Claude Desktop
1. Open Claude Desktop settings
2. Navigate to the Privacy section
3. **Disable "Help Improve Claude"** - This prevents your chats and coding sessions from being used to train and improve Anthropic AI models
4. This ensures your IONIX security data remains private and is not used for model training purposes

### Other AI Tools
If you're using other AI agents or tools with this MCP server:
- Look for similar privacy settings related to "data collection," "training," or "model improvement"
- Disable any options that allow your conversations or data to be used for training purposes
- Review the tool's privacy policy to understand how your data is handled

**Why This Matters:** The IONIX MCP server provides access to sensitive security information including vulnerabilities, assets, and risk assessments. Ensuring this data is not collected or used for training purposes is critical for maintaining your organization's security posture and compliance requirements.

## Best Practices & Limitations

### Context Window Limitations

Large Language Models (LLMs) like Claude have a limited context window, which means they can only process a certain amount of information at once. To get the best results when using the IONIX MCP server:

**Do:**
- Ask for specific, filtered data (e.g., "Show me critical action items from the last week")
- Use aggregated scan data from `get_scan_history` for historical analysis
- Apply filters to narrow down results (e.g., by asset, risk score, urgency, date range)
- Request summaries and counts for large datasets

**Avoid:**
- Requesting all action items without filters (this will likely exceed the context window)
- Asking for complete exports of large datasets
- Queries that return hundreds or thousands of individual items without aggregation

**Example of Good Queries:**
- "What are the high urgency action items for assets containing 'production' from the last 7 days?"
- "Show me scan history for the last 5 scans and compare the number of critical findings"
- "Get organization assets with risk score 'High' or 'Critical' that have open ports 22,3389"

**Example of Problematic Queries:**
- "Show me all action items" (too broad, will fill context window)
- "List every asset in our organization with all their details" (too much data)

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

**Scan History & Trends:**
- "Show me the last 2 scan results"
- "Get scan history for the last 5 scans"
- "Compare action items across the last 3 scans"
- "Show me the scan duration and asset counts from recent scans"

### Multi-Account Support

All tools support an optional `account_name` parameter for querying different IONIX accounts (for MSSPs).

## Available Tools

The IONIX MCP server provides the following tools:

### Discovery & Assets
- `get_discovery_org_assets` - Get organization assets with comprehensive filtering (technologies, IPs, ports, CVEs, etc.)
- `get_discovery_certificates` - Get SSL/TLS certificates
- `get_discovery_connections` - Get asset connections
- `get_discovery_technologies` - Get technologies discovered on assets
- `get_discovery_logins` - Get login assets
- `get_discovery_managed_domains` - Get managed domains

### Security Assessments
- `get_attack_surface_risk_score` - Get attack surface risk scores
- `get_attack_surface_risk_score_details` - Get detailed risk score information
- `get_attack_surface_risk_score_issues` - Get issues contributing to risk scores
- `get_assessments_digital_supply_chain` - Get external assets from digital supply chain assessment
- `get_assessments_org_assets` - Get organization assets from assessments page

### Remediation & Action Items
- `get_action_items_open` - Get open action items with urgency and time filtering
- `get_action_items_open_detailed` - Get detailed open action items
- `get_action_items_closed` - Get closed action items
- `get_action_items_all` - Get all action items (open and closed)

### Scan History & Analytics
- `get_scan_history` - **NEW!** Get aggregated scan history showing:
  - Scan metadata (timestamp, type, duration, scan ID)
  - Asset counts by type (domains, subdomains, IPs, certificates, connections)
  - Action items breakdown by type and urgency
  - Scan-to-scan changes (opened, closed, reopened items)
  - Infrastructure details (IP networks, cloud assets, compromised machines)

### Testing & Dashboard
- `get_tests` - Get security test results
- `get_dashboard_geomap` - Get geographic map data

### MSSP Management
- `get_mssp_company` - Get MSSP company information
- `list_mssp_sub_accounts` - List MSSP sub-accounts with extensive filtering options
- `get_mssp_sub_account` - Get a specific MSSP sub-account by company name

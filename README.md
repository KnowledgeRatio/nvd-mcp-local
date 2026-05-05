# nvd-mcp

A local MCP server for the [National Vulnerability Database (NVD) API v2](https://nvd.nist.gov/developers/vulnerabilities) and the [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Exposes NVD search and CISA KEV data as tools and prompts for use with VS Code / GitHub Copilot and Claude Code.

## Prerequisites

- Node.js 18 or later
- An NVD API key (optional but recommended — free at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key))

Without an API key the server works at 5 requests/30 seconds. With one it is 50 requests/30 seconds.

## Installation

```bash
git clone <this-repo>
cd nvd-mcp
npm install
```

## Configuration

### VS Code / GitHub Copilot

Add the following to your workspace `.vscode/mcp.json`. VS Code will prompt for your API key as a password field on first use — it is stored in VS Code secret storage and never written to disk.

```json
{
  "servers": {
    "nvd": {
      "type": "stdio",
      "command": "node",
      "args": ["${workspaceFolder}/nvd-mcp/index.js"],
      "env": {
        "NVD_API_KEY": "${input:nvdApiKey}"
      }
    }
  },
  "inputs": [
    {
      "id": "nvdApiKey",
      "type": "promptString",
      "description": "NVD API Key (get one free at https://nvd.nist.gov/developers/request-an-api-key)",
      "password": true
    }
  ]
}
```

### Claude Code

Add the following to your workspace `.mcp.json`. Set `NVD_API_KEY` as a Windows user environment variable so it is never stored in a file:

```powershell
[System.Environment]::SetEnvironmentVariable("NVD_API_KEY", "your-key-here", "User")
```

Then restart VS Code and add to `.mcp.json`:

```json
{
  "mcpServers": {
    "nvd": {
      "type": "stdio",
      "command": "node",
      "args": ["nvd-mcp/index.js"]
    }
  }
}
```

## Tools

### `search_cves`

Search the NVD for CVEs by keyword, severity, date range, or CISA KEV status.

| Parameter | Type | Description |
|-----------|------|-------------|
| `keyword` | string | Keyword to search in CVE descriptions |
| `exact_match` | boolean | Require the keyword to match as an exact phrase |
| `severity` | string | Filter by CVSS v3 severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `has_kev` | boolean | Only return CVEs on the CISA KEV list |
| `pub_start_date` | string | Published on or after (ISO 8601, e.g. `2024-01-01T00:00:00.000`) |
| `pub_end_date` | string | Published on or before (ISO 8601) |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `get_cve`

Get full details for a specific CVE including CVSS scores, affected product configurations, and references.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cve_id` | string | CVE identifier, e.g. `CVE-2021-44228` |

---

### `search_cves_by_cpe`

Find all CVEs affecting a specific product by its CPE 2.3 URI. Use `search_cpes` first if you do not know the exact CPE string.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cpe_name` | string | CPE 2.3 URI, e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `get_recent_cves`

Get CVEs published in the last N days, optionally filtered by severity or KEV status.

| Parameter | Type | Description |
|-----------|------|-------------|
| `days` | number | How many days back to look (default 7) |
| `severity` | string | Filter by CVSS v3 severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `has_kev` | boolean | Only return CVEs on the CISA KEV list |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `search_cpes`

Search for CPE product entries by name or vendor keyword. Use this to find the exact CPE URI needed for `search_cves_by_cpe`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `keyword` | string | Product name or vendor, e.g. `apache tomcat` or `openssl` |
| `cpe_match_string` | string | Partial CPE 2.3 string to match, e.g. `cpe:2.3:a:microsoft` |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `get_kev`

Fetch the CISA Known Exploited Vulnerabilities catalog live. With no arguments returns a summary and the 10 most recent additions. All filters compose.

| Parameter | Type | Description |
|-----------|------|-------------|
| `keyword` | string | Filter by vendor, product, or vulnerability name (case-insensitive) |
| `since` | string | Only entries added on or after this date (`YYYY-MM-DD`) |
| `ransomware_only` | boolean | Only return entries with a known ransomware campaign association |
| `results_per_page` | number | Results to return, max 50 (default 10) |

## Prompts

Prompts are pre-defined workflows that chain multiple tool calls and instruct the model to produce a structured report. In VS Code they are available via the Copilot Chat prompt picker.

### `cve-analysis`

Full analysis of a single CVE. Calls `get_cve` and `get_kev`, then produces a structured report covering severity, CVSS vector breakdown, exploitability, KEV and ransomware status, affected versions, remediation guidance, and key references.

**Argument:** `cve_id` — e.g. `CVE-2021-44228`

---

### `vulnerability-brief`

Vulnerability exposure brief for a product. Chains `search_cpes` to find the CPE, `search_cves_by_cpe` for associated CVEs, and `search_cves` with `has_kev=true` to surface KEV entries. Outputs a prioritised exposure summary with a security team recommendation.

**Argument:** `product` — e.g. `Apache Log4j` or `Cisco IOS`

---

### `weekly-threat-digest`

Digest of new threats from the past 7 days. Calls `get_recent_cves` for CRITICAL and HIGH CVEs and `get_kev` for newly added KEV entries. Outputs a structured digest with a prioritised action list.

**No arguments.**

## Typical workflows

**Look up a CVE you have heard about:**
> Use the `cve-analysis` prompt with the CVE ID.

**Assess exposure for a product you run:**
> Use the `vulnerability-brief` prompt with the product name.

**Monday morning threat check:**
> Use the `weekly-threat-digest` prompt with no arguments.

**Find exploited vulnerabilities in a specific vendor's products:**
> Call `get_kev` with `keyword` set to the vendor name.

**Check if a specific product version has known CVEs:**
> Call `search_cpes` with the product name, then `search_cves_by_cpe` with the CPE URI returned.

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

## How the tools work

All tools return compact, token-efficient output. List tools return one line per result. `get_cve` returns structured markdown. This is intentional — the server is designed to be lean so tool responses do not consume large portions of your context window.

### Data sources

There are two data sources in use and it is worth understanding the difference:

**NVD API** — queried by `search_cves`, `get_cve`, `search_cves_by_cpe`, `get_recent_cves`, and `search_cpes`. Every call is a targeted HTTP request to NVD's REST API, which returns only the records matching your query. NVD also maintains a cross-reference to the CISA KEV catalog, surfaced via the `has_kev` parameter. This cross-reference may lag behind CISA by some hours or days as NVD syncs on their own schedule.

**CISA KEV catalog** — queried only by `get_kev`. CISA publishes the full catalog as a single static JSON file (~500 KB, ~1,200 entries). There is no query API, so `get_kev` downloads the entire catalog on every call and filters in memory. This is the authoritative source for KEV data and is always current, but it costs more tokens than an equivalent NVD query because the download and filtering happen locally.

### KEV: two approaches

There are two ways to check whether a CVE is on the CISA KEV list, with different tradeoffs:

| Approach | How it works | Freshness | Token cost |
|----------|-------------|-----------|------------|
| `has_kev: true` on `search_cves` or `get_recent_cves` | NVD filters results server-side using their own KEV cross-reference | May lag behind CISA by hours or days | Low — output is the same compact list as any other search |
| `get_kev` with a `keyword` or `since` filter | Downloads full CISA catalog, filters locally | Always current | Higher — full catalog is fetched every call |

Use `has_kev` when you are already searching CVEs and want to narrow results to exploited ones — it adds no overhead. Use `get_kev` when you need the authoritative CISA data, want fields that NVD does not carry (`requiredAction`, `dueDate`, ransomware flag), or need to be certain you have the latest additions.

## Tools

### `search_cves`

Queries the NVD API. Returns one line per result: CVE ID, CVSS score, severity, publication date, and a short description. Results are capped at 50 to keep responses lean.

| Parameter | Type | Description |
|-----------|------|-------------|
| `keyword` | string | Keyword to search in CVE descriptions |
| `exact_match` | boolean | Require the keyword to match as an exact phrase |
| `severity` | string | Filter by CVSS v3 severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `has_kev` | boolean | Only return CVEs on the CISA KEV list (filtered by NVD — see note above) |
| `pub_start_date` | string | Published on or after (ISO 8601, e.g. `2024-01-01T00:00:00.000`) |
| `pub_end_date` | string | Published on or before (ISO 8601) |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `get_cve`

Queries the NVD API for a single CVE and returns a structured markdown report. This is the most detailed output any tool produces: CVSS score and version, decoded vector components, exploitability and impact sub-scores, affected version ranges parsed from CPE configurations, CWE classifications, and up to 5 references with their tags.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cve_id` | string | CVE identifier, e.g. `CVE-2021-44228` |

---

### `search_cves_by_cpe`

Queries the NVD API for all CVEs associated with a specific CPE URI. Returns one line per result in the same compact format as `search_cves`. If you do not know the exact CPE URI, use `search_cpes` first.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cpe_name` | string | CPE 2.3 URI, e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `get_recent_cves`

Queries the NVD API for CVEs published within the last N days. Returns one line per result. Useful for regular threat monitoring.

| Parameter | Type | Description |
|-----------|------|-------------|
| `days` | number | How many days back to look (default 7) |
| `severity` | string | Filter by CVSS v3 severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `has_kev` | boolean | Only return CVEs on the CISA KEV list (filtered by NVD — see note above) |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `search_cpes`

Queries the NVD API for CPE product entries matching a name or keyword. Returns one line per result: the full CPE 2.3 URI and the product's human-readable title. Use this to find the exact URI you need before calling `search_cves_by_cpe`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `keyword` | string | Product name or vendor, e.g. `apache tomcat` or `openssl` |
| `cpe_match_string` | string | Partial CPE 2.3 string to match, e.g. `cpe:2.3:a:microsoft` |
| `results_per_page` | number | Results to return, max 50 (default 20) |

---

### `get_kev`

Downloads the full CISA KEV catalog (~500 KB, ~1,200 entries) on every call and filters in memory. This is the only tool that does not query the NVD API and the only one that fetches a full dataset rather than a targeted query.

Because the entire catalog is downloaded each time, this tool consumes more tokens than the NVD tools when used frequently. The default of 10 results is intentionally low. If you only need to check whether CVEs from a search are on the KEV list, prefer `has_kev: true` on `search_cves` or `get_recent_cves` instead — that delegates filtering to NVD at no extra cost.

Use `get_kev` when you need CISA-authoritative data or fields that NVD does not expose: `requiredAction`, `dueDate`, and the ransomware campaign flag.

| Parameter | Type | Description |
|-----------|------|-------------|
| `keyword` | string | Filter by vendor, product, or vulnerability name (case-insensitive) |
| `since` | string | Only entries added on or after this date (`YYYY-MM-DD`) |
| `ransomware_only` | boolean | Only return entries with a known ransomware campaign association |
| `results_per_page` | number | Results to return, max 50 (default 10) |

## Prompts

Prompts are pre-defined workflows that chain multiple tool calls and instruct the model to produce a structured report. In VS Code they are available via the Copilot Chat prompt picker.

### `cve-analysis`

Full analysis of a single CVE. Calls `get_cve` for NVD data and `get_kev` filtered by CVE ID for CISA-authoritative KEV status. Produces a structured report covering severity, decoded CVSS vector, exploitability, KEV and ransomware status, affected versions, remediation guidance derived from available data, and key references.

**Argument:** `cve_id` — e.g. `CVE-2021-44228`

---

### `vulnerability-brief`

Vulnerability exposure brief for a product. Chains `search_cpes` to resolve the CPE URI, `search_cves_by_cpe` for associated CVEs, and `search_cves` with `has_kev: true` to surface KEV entries via NVD. Outputs a prioritised exposure summary with a security team recommendation.

**Argument:** `product` — e.g. `Apache Log4j` or `Cisco IOS`

---

### `weekly-threat-digest`

Digest of new threats from the past 7 days. Calls `get_recent_cves` twice (CRITICAL and HIGH severity) via NVD, and `get_kev` with a rolling 7-day `since` filter for newly added KEV entries direct from CISA. Outputs a structured digest with a prioritised action list.

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

**Narrow a CVE search to actively exploited vulnerabilities only:**
> Use `has_kev: true` on `search_cves` or `get_recent_cves` — this is more token-efficient than `get_kev` for filtering within a search.

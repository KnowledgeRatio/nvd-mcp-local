#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json";
const API_KEY = process.env.NVD_API_KEY;

function nvdHeaders() {
  return API_KEY ? { apiKey: API_KEY } : {};
}

async function nvdGet(path, params = {}) {
  const url = new URL(`${NVD_BASE}${path}`);
  for (const [k, v] of Object.entries(params)) {
    if (v != null) url.searchParams.set(k, String(v));
  }
  const res = await fetch(url.toString(), { headers: nvdHeaders() });
  if (!res.ok) throw new Error(`NVD API ${res.status}: ${res.statusText}`);
  return res.json();
}

function cvssEntry(metrics) {
  return metrics?.cvssMetricV31?.[0] ?? metrics?.cvssMetricV30?.[0] ?? metrics?.cvssMetricV2?.[0];
}

function cvssVersion(metrics) {
  return metrics?.cvssMetricV31 ? "3.1" : metrics?.cvssMetricV30 ? "3.0" : metrics?.cvssMetricV2 ? "2.0" : null;
}

const CVSS_LABELS = {
  AV:  { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  AC:  { L: "Low", H: "High" },
  PR:  { N: "None", L: "Low", H: "High" },
  UI:  { N: "None", R: "Required" },
  S:   { U: "Unchanged", C: "Changed" },
  C:   { H: "High", L: "Low", N: "None" },
  I:   { H: "High", L: "Low", N: "None" },
  A:   { H: "High", L: "Low", N: "None" },
};

const CVSS_NAMES = {
  AV: "Attack Vector", AC: "Attack Complexity", PR: "Privileges Required",
  UI: "User Interaction", S: "Scope", C: "Confidentiality", I: "Integrity", A: "Availability",
};

function decodeCvssVector(vector) {
  if (!vector) return "";
  return vector.split("/").slice(1)
    .map((p) => {
      const [k, v] = p.split(":");
      return `${CVSS_NAMES[k] ?? k}: ${CVSS_LABELS[k]?.[v] ?? v}`;
    })
    .join(" | ");
}

function parseAffectedVersions(configurations) {
  if (!configurations?.length) return [];
  const ranges = new Set();
  for (const config of configurations) {
    for (const node of config.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        if (!match.vulnerable) continue;
        const parts = match.criteria?.split(":") ?? [];
        const vendor = parts[3] ?? "";
        const product = parts[4] ?? "";
        const ver = parts[5];
        let range = `${vendor} ${product}`;
        if (match.versionStartIncluding) range += ` >=${match.versionStartIncluding}`;
        else if (match.versionStartExcluding) range += ` >${match.versionStartExcluding}`;
        if (match.versionEndExcluding) range += ` <${match.versionEndExcluding}`;
        else if (match.versionEndIncluding) range += ` <=${match.versionEndIncluding}`;
        else if (ver && ver !== "*") range += ` ${ver}`;
        ranges.add(range.trim());
      }
    }
  }
  return [...ranges].slice(0, 10);
}

// Compact single-line format used by list tools
function formatCve(vuln) {
  const cve = vuln.cve;
  const entry = cvssEntry(cve.metrics);
  const score = entry?.cvssData?.baseScore ?? "N/A";
  const sev = (entry?.baseSeverity ?? entry?.cvssData?.baseSeverity ?? "N/A").padEnd(8);
  const published = cve.published?.slice(0, 10) ?? "unknown";
  const desc = cve.descriptions?.find((d) => d.lang === "en")?.value ?? "";
  const short = desc.length > 100 ? desc.slice(0, 97) + "..." : desc;
  return `${cve.id}  ${score} ${sev}  ${published}  ${short}`;
}

function formatCveList(data) {
  const total = data.totalResults ?? 0;
  const vulns = data.vulnerabilities ?? [];
  return `${total} results (showing ${vulns.length}):\n${vulns.map(formatCve).join("\n")}`;
}

// Full structured format used by get_cve
function formatCveDetail(vuln) {
  const cve = vuln.cve;
  const entry = cvssEntry(cve.metrics);
  const ver = cvssVersion(cve.metrics);
  const score = entry?.cvssData?.baseScore ?? "N/A";
  const sev = entry?.baseSeverity ?? entry?.cvssData?.baseSeverity ?? "N/A";
  const vector = entry?.cvssData?.vectorString ?? "";
  const exploitScore = entry?.exploitabilityScore;
  const impactScore = entry?.impactScore;
  const desc = cve.descriptions?.find((d) => d.lang === "en")?.value ?? "No description";

  const cwes = cve.weaknesses
    ?.flatMap((w) => w.description?.filter((d) => d.lang === "en").map((d) => d.value) ?? [])
    .filter(Boolean) ?? [];

  const refs = (cve.references ?? []).slice(0, 5).map((r) => {
    const tags = r.tags?.length ? ` [${r.tags.join(", ")}]` : "";
    return `- ${r.url}${tags}`;
  });

  const affected = parseAffectedVersions(cve.configurations);

  const lines = [
    `# ${cve.id}`,
    `Score: ${score} ${sev}${ver ? ` (CVSS ${ver})` : ""}` +
      (exploitScore != null ? ` | Exploitability: ${exploitScore}` : "") +
      (impactScore != null ? ` | Impact: ${impactScore}` : ""),
    `Published: ${cve.published?.slice(0, 10)} | Modified: ${cve.lastModified?.slice(0, 10)}`,
    "",
    desc,
  ];

  if (vector) {
    lines.push("", `Vector: ${vector}`, decodeCvssVector(vector));
  }
  if (cwes.length) lines.push("", `Weaknesses: ${cwes.join(", ")}`);
  if (affected.length) {
    lines.push("", "Affected versions:");
    affected.forEach((a) => lines.push(`- ${a}`));
  }
  if (refs.length) {
    lines.push("", "References:");
    lines.push(...refs);
  }

  return lines.join("\n");
}

function formatCveHistory(data) {
  const total = data.totalResults ?? 0;
  const changes = data.cveChanges ?? [];
  if (!changes.length) return `${total} results (showing 0): no change history found.`;

  const lines = [`${total} results (showing ${changes.length}):`];
  for (const item of changes) {
    const c = item.change;
    lines.push(`\n${c.cveId}  [${c.eventName}]  ${c.created?.slice(0, 10) ?? "unknown"}`);
    if (c.sourceIdentifier) lines.push(`  Source: ${c.sourceIdentifier}`);
    if (c.details?.length) {
      for (const d of c.details) {
        const val = d.newValue ? ` → ${d.newValue}` : d.oldValue ? ` (removed: ${d.oldValue})` : "";
        lines.push(`  ${d.action ?? ""} ${d.type ?? ""}${val}`.trimEnd());
      }
    }
  }
  return lines.join("\n");
}

function formatCpeList(data) {
  const total = data.totalResults ?? 0;
  const products = data.products ?? [];
  const lines = products.map((p) => {
    const cpe = p.cpe;
    const title = cpe.titles?.find((t) => t.lang === "en")?.title ?? "";
    return `${cpe.cpeName}${title ? `  (${title})` : ""}`;
  });
  return `${total} results (showing ${products.length}):\n${lines.join("\n")}`;
}

const PAGE_MAX = 50;
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

async function fetchKev() {
  const res = await fetch(KEV_URL);
  if (!res.ok) throw new Error(`CISA KEV fetch failed: ${res.status}`);
  return res.json();
}

function formatKevEntry(v) {
  const ransomware = v.knownRansomwareCampaignUse === "Known" ? " [RANSOMWARE]" : "";
  return `${v.cveID}${ransomware}  ${v.vendorProject} ${v.product}  Added: ${v.dateAdded}  Due: ${v.dueDate}\n  ${v.vulnerabilityName} — ${v.requiredAction}`;
}

const server = new Server(
  { name: "nvd", version: "1.0.0" },
  { capabilities: { tools: {}, prompts: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "search_cves",
      description:
        "Search the NVD for CVEs by keyword, CVSS severity, publication date range, or CISA KEV status",
      inputSchema: {
        type: "object",
        properties: {
          keyword: {
            type: "string",
            description: "Keyword to search in CVE descriptions",
          },
          exact_match: {
            type: "boolean",
            description: "Require the keyword to match as an exact phrase (default false)",
          },
          severity: {
            type: "string",
            enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            description: "Filter by CVSS v3 severity",
          },
          has_kev: {
            type: "boolean",
            description: "If true, only return CVEs on CISA's Known Exploited Vulnerabilities list",
          },
          pub_start_date: {
            type: "string",
            description:
              "Published on or after (ISO 8601, e.g. 2024-01-01T00:00:00.000)",
          },
          pub_end_date: {
            type: "string",
            description: "Published on or before (ISO 8601)",
          },
          results_per_page: {
            type: "number",
            description: "Results to return, max 50 (default 20)",
          },
        },
      },
    },
    {
      name: "get_cve",
      description:
        "Get full details for a specific CVE — CVSS scores, affected products, references",
      inputSchema: {
        type: "object",
        required: ["cve_id"],
        properties: {
          cve_id: {
            type: "string",
            description: "CVE identifier, e.g. CVE-2021-44228",
          },
        },
      },
    },
    {
      name: "search_cves_by_cpe",
      description: "Find all CVEs that affect a specific product by its CPE name",
      inputSchema: {
        type: "object",
        required: ["cpe_name"],
        properties: {
          cpe_name: {
            type: "string",
            description:
              "CPE 2.3 URI, e.g. cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
          },
          results_per_page: {
            type: "number",
            description: "Results to return (default 20)",
          },
        },
      },
    },
    {
      name: "get_recent_cves",
      description:
        "Get CVEs published in the last N days, optionally filtered by severity",
      inputSchema: {
        type: "object",
        properties: {
          days: {
            type: "number",
            description: "How many days back to look (default 7)",
          },
          severity: {
            type: "string",
            enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          },
          has_kev: {
            type: "boolean",
            description: "If true, only return CVEs on CISA's Known Exploited Vulnerabilities list",
          },
          results_per_page: {
            type: "number",
            description: "Results to return, max 50 (default 20)",
          },
        },
      },
    },
    {
      name: "search_cpes",
      description:
        "Search for CPE product entries by name or keyword — use this to find the exact CPE URI needed for search_cves_by_cpe",
      inputSchema: {
        type: "object",
        properties: {
          keyword: {
            type: "string",
            description: "Product name or vendor keyword, e.g. 'apache tomcat' or 'openssl'",
          },
          cpe_match_string: {
            type: "string",
            description: "Partial CPE 2.3 string to match against, e.g. cpe:2.3:a:microsoft",
          },
          results_per_page: {
            type: "number",
            description: "Results to return, max 50 (default 20)",
          },
        },
      },
    },
    {
      name: "get_cve_history",
      description:
        "Retrieve the change history for CVE records, showing how vulnerabilities have been updated over time",
      inputSchema: {
        type: "object",
        properties: {
          cve_id: {
            type: "string",
            description:
              "Retrieve change history for a specific CVE identifier (e.g. CVE-2021-44228). Leave empty to query by date range instead.",
          },
          change_start_date: {
            type: "string",
            description:
              "Start of the change event date range (ISO 8601, e.g. 2024-01-01T00:00:00.000). Maximum range is 120 days.",
          },
          change_end_date: {
            type: "string",
            description:
              "End of the change event date range (ISO 8601, e.g. 2024-03-31T23:59:59.999). Maximum range is 120 days.",
          },
          event_name: {
            type: "string",
            description:
              "Filter by event type, e.g. 'Initial Analysis', 'Reanalysis', 'CVE Modified', 'CVE Rejected', 'CVE Translated'.",
          },
          results_per_page: {
            type: "number",
            description: "Results to return (1–5000, default 20)",
          },
          start_index: {
            type: "number",
            description: "Zero-based index of the first result to return, used for pagination (default 0)",
          },
        },
      },
    },
    {
      name: "get_kev",
      description:
        "Fetch the CISA Known Exploited Vulnerabilities catalog live. No args returns a summary + 10 most recent additions. Filter by keyword, date, or ransomware association.",
      inputSchema: {
        type: "object",
        properties: {
          keyword: {
            type: "string",
            description: "Filter by vendor, product, or vulnerability name (case-insensitive)",
          },
          since: {
            type: "string",
            description: "Only entries added to KEV on or after this date (YYYY-MM-DD)",
          },
          ransomware_only: {
            type: "boolean",
            description: "If true, only return entries with a known ransomware campaign association",
          },
          results_per_page: {
            type: "number",
            description: "Max entries to return, max 50 (default 10)",
          },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "search_cves": {
        const params = { resultsPerPage: Math.min(args.results_per_page ?? 20, PAGE_MAX) };
        if (args.keyword) params.keywordSearch = args.keyword;
        if (args.exact_match) params.keywordExactMatch = true;
        if (args.severity) params.cvssV3Severity = args.severity;
        if (args.has_kev) params.hasKev = true;
        if (args.pub_start_date) params.pubStartDate = args.pub_start_date;
        if (args.pub_end_date) params.pubEndDate = args.pub_end_date;
        const data = await nvdGet("/cves/2.0", params);
        return { content: [{ type: "text", text: formatCveList(data) }] };
      }

      case "get_cve": {
        const data = await nvdGet("/cves/2.0", { cveId: args.cve_id });
        if (!data.vulnerabilities?.length) {
          return { content: [{ type: "text", text: `No CVE found with ID: ${args.cve_id}` }] };
        }
        return { content: [{ type: "text", text: formatCveDetail(data.vulnerabilities[0]) }] };
      }

      case "search_cves_by_cpe": {
        const params = {
          cpeName: args.cpe_name,
          resultsPerPage: Math.min(args.results_per_page ?? 20, PAGE_MAX),
        };
        const data = await nvdGet("/cves/2.0", params);
        return { content: [{ type: "text", text: formatCveList(data) }] };
      }

      case "get_recent_cves": {
        const days = args.days ?? 7;
        const now = new Date();
        const past = new Date(now.getTime() - days * 86400000);
        const fmt = (d) => d.toISOString().replace("Z", ".000");
        const params = {
          pubStartDate: fmt(past),
          pubEndDate: fmt(now),
          resultsPerPage: Math.min(args.results_per_page ?? 20, PAGE_MAX),
        };
        if (args.severity) params.cvssV3Severity = args.severity;
        if (args.has_kev) params.hasKev = true;
        const data = await nvdGet("/cves/2.0", params);
        return { content: [{ type: "text", text: formatCveList(data) }] };
      }

      case "search_cpes": {
        const params = { resultsPerPage: Math.min(args.results_per_page ?? 20, PAGE_MAX) };
        if (args.keyword) params.keywordSearch = args.keyword;
        if (args.cpe_match_string) params.cpeMatchString = args.cpe_match_string;
        const data = await nvdGet("/cpes/2.0", params);
        return { content: [{ type: "text", text: formatCpeList(data) }] };
      }

      case "get_cve_history": {
        const params = {
          resultsPerPage: Math.min(Math.max(1, args.results_per_page ?? 20), 5000),
          startIndex: Math.max(0, args.start_index ?? 0),
        };
        if (args.cve_id) params.cveId = args.cve_id;
        if (args.change_start_date) params.changeStartDate = args.change_start_date;
        if (args.change_end_date) params.changeEndDate = args.change_end_date;
        if (args.event_name) params.eventName = args.event_name;
        const data = await nvdGet("/cvehistory/2.0", params);
        return { content: [{ type: "text", text: formatCveHistory(data) }] };
      }

      case "get_kev": {
        const catalog = await fetchKev();
        let vulns = catalog.vulnerabilities ?? [];

        if (args.since) {
          vulns = vulns.filter((v) => v.dateAdded >= args.since);
        }
        if (args.ransomware_only) {
          vulns = vulns.filter((v) => v.knownRansomwareCampaignUse === "Known");
        }
        if (args.keyword) {
          const kw = args.keyword.toLowerCase();
          vulns = vulns.filter(
            (v) =>
              v.vendorProject?.toLowerCase().includes(kw) ||
              v.product?.toLowerCase().includes(kw) ||
              v.vulnerabilityName?.toLowerCase().includes(kw) ||
              v.cveID?.toLowerCase().includes(kw)
          );
        }

        const limit = Math.min(args.results_per_page ?? 10, PAGE_MAX);
        const sorted = [...vulns].sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
        const page = sorted.slice(0, limit);
        const ransomwareCount = vulns.filter((v) => v.knownRansomwareCampaignUse === "Known").length;

        const summary = [
          `CISA KEV Catalog | Version: ${catalog.catalogVersion} | Released: ${catalog.dateReleased}`,
          `Matched: ${vulns.length} entries (${ransomwareCount} ransomware-associated) | Showing ${page.length} most recent`,
          "",
        ].join("\n");

        return { content: [{ type: "text", text: summary + page.map(formatKevEntry).join("\n\n") }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err.message}` }],
      isError: true,
    };
  }
});

const PROMPTS = [
  {
    name: "cve-analysis",
    description: "Full triage of a single CVE: severity, exploitability, KEV status, ransomware association, affected versions, and remediation guidance from available data",
    arguments: [
      { name: "cve_id", description: "CVE identifier, e.g. CVE-2021-44228", required: true },
    ],
  },
  {
    name: "vulnerability-brief",
    description: "Vulnerability exposure brief for a product: find its CPE, list CVEs, highlight KEV entries and critical issues",
    arguments: [
      { name: "product", description: "Product or vendor name, e.g. 'Apache Log4j' or 'Cisco IOS'", required: true },
    ],
  },
  {
    name: "weekly-threat-digest",
    description: "Digest of new critical/high CVEs and fresh KEV additions from the past 7 days",
    arguments: [],
  },
];

server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: PROMPTS }));

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "cve-analysis": {
      const id = args?.cve_id;
      return {
        description: PROMPTS[0].description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Triage ${id} using the nvd tools. Follow these steps:
1. Call get_cve with cve_id="${id}" to retrieve full details.
2. Call get_kev with keyword="${id}" to check CISA KEV status.

Then produce a structured triage report with these sections:
**Overview** — one-line summary of what is vulnerable and how.
**Severity** — CVSS score, version (v2/v3), severity rating, and full vector string with each component explained.
**Exploitability** — attack vector, complexity, privileges required, user interaction, scope. Flag if remotely exploitable with no auth.
**KEV Status** — is it on the CISA Known Exploited Vulnerabilities list? If yes: date added, due date, required action, ransomware association.
**Affected Versions** — list affected CPE version ranges from the CVE configurations if present.
**Remediation** — derive guidance from: KEV requiredAction (if present), CWE category mitigations, CVSS vector constraints, and reference URLs. Be explicit about what is known vs inferred.
**References** — top 3-5 links from the CVE record, prioritising vendor advisories and patches over generic NVD links.`,
            },
          },
        ],
      };
    }

    case "vulnerability-brief": {
      const product = args?.product;
      return {
        description: PROMPTS[1].description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Generate a vulnerability brief for "${product}" using the nvd tools. Follow these steps:
1. Call search_cpes with keyword="${product}" to find matching CPE entries.
2. For the most relevant CPE(s) found, call search_cves_by_cpe to retrieve associated CVEs.
3. Call search_cves with keyword="${product}" and has_kev=true to find any KEV entries.

Then produce a brief with these sections:
**Product** — confirmed product name and vendor from CPE results.
**Exposure Summary** — total CVE count, breakdown by severity (CRITICAL / HIGH / MEDIUM / LOW), date range of known vulnerabilities.
**KEV Entries** — list any CVEs on the CISA Known Exploited Vulnerabilities list with their required actions and due dates.
**Top Risks** — the 3-5 highest severity CVEs with score, vector summary, and a one-line description.
**Recommendation** — based on KEV status and severity distribution, what should a security team prioritise?`,
            },
          },
        ],
      };
    }

    case "weekly-threat-digest": {
      return {
        description: PROMPTS[2].description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Generate a weekly threat digest using the nvd tools. Follow these steps:
1. Call get_recent_cves with days=7, severity="CRITICAL", results_per_page=20 to get new critical CVEs.
2. Call get_recent_cves with days=7, severity="HIGH", results_per_page=20 to get new high CVEs.
3. Call get_kev with since="${new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10)}" to get CVEs newly added to CISA KEV this week.

Then produce a digest with these sections:
**Week in Review** — total new CRITICAL and HIGH CVEs published, total new KEV additions.
**New KEV Additions** — list every CVE added to the CISA Known Exploited Vulnerabilities list this week. Include vendor, product, required action, due date, and ransomware flag.
**Critical CVEs to Watch** — top 5 critical CVEs by score with a one-line summary each.
**Notable High CVEs** — 3-5 high severity CVEs worth tracking, prioritising those that are remotely exploitable without authentication (check CVSS vector).
**Action Items** — concise list of what a security team should do this week based on the above.`,
            },
          },
        ],
      };
    }

    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);

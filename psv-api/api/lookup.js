"use strict";

const { isIP } = require("node:net");

const ALLOWED_ORIGINS = new Set([
  "https://privacyskillvault.com",
  "https://www.privacyskillvault.com"
]);
const MAX_BODY_BYTES = 2048;
const TIMEOUT_MS = 8000;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 20;
const requestBuckets = new Map();

function isRateLimited(req) {
  const clientIp = req.headers && req.headers["x-real-ip"];
  const key = typeof clientIp === "string" && clientIp ? clientIp : "unknown-client";
  const now = Date.now();
  const current = requestBuckets.get(key);
  if (!current || now - current.startedAt >= RATE_WINDOW_MS) {
    requestBuckets.set(key, { startedAt: now, count: 1 });
    return false;
  }
  current.count += 1;
  return current.count > RATE_LIMIT;
}

function json(res, status, payload) {
  return res.status(status).json(payload);
}

function setHeaders(res, origin) {
  res.setHeader("Vary", "Origin");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Max-Age", "600");
  }
}

function normalizeIndicator(input) {
  if (typeof input !== "string") return null;
  let value = input.trim();
  if (!value || value.length > 2048 || /[\r\n\0]/.test(value)) return null;

  if (/^hxxps?:\/\//i.test(value)) value = value.replace(/^hxxps?/i, match => match.toLowerCase().startsWith("hxxps") ? "https" : "http");
  value = value.replace(/\[\.\]/g, ".");

  if (/^https?:\/\//i.test(value)) {
    try {
      const parsed = new URL(value);
      if (parsed.username || parsed.password) return null;
      if (!["http:", "https:"].includes(parsed.protocol)) return null;
      value = parsed.hostname.toLowerCase();
    } catch (_) { return null; }
  }

  value = value.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  const ipVersion = isIP(value);
  if (ipVersion === 4) {
    const octets = value.split(".").map(Number);
    const [a,b,c] = octets;
    const blocked =
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && c <= 2) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113);
    return blocked ? null : { value, type: "IPv4", isIp: true };
  }
  if (ipVersion === 6) {
    if (value === "::1" || value === "::" || /^fe[89ab]/.test(value) || /^fc|^fd/.test(value) || /^ff/.test(value)) return null;
    return { value, type: "IPv6", isIp: true };
  }
  if (/^CVE-\d{4}-\d{4,}$/i.test(value)) return { value: value.toUpperCase(), type: "CVE", isCve: true };
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)) return { value, type: "file", isHash: true };
  if (value.length > 253 || !value.includes(".")) return null;
  const labels = value.split(".");
  if (!labels.every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
  if (!/[a-z]/.test(labels[labels.length - 1])) return null;
  if (["localhost","local","internal","test","invalid","example","onion"].includes(labels[labels.length - 1])) return null;
  return { value, type: "domain", isDomain: true };
}

async function fetchJson(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal, headers: { Accept: "application/json", ...(options.headers || {}) } });
    const text = await response.text();
    if (text.length > 1_000_000) throw new Error("Provider response exceeded the allowed size");
    let body = {};
    try { body = text ? JSON.parse(text) : {}; } catch (_) { throw new Error("Provider returned an invalid response"); }
    if (!response.ok) {
      const providerMessage = body && (body.message || body.error || body.detail || body.reason);
      const error = new Error("Provider returned HTTP " + response.status);
      error.status = response.status;
      error.providerMessage = typeof providerMessage === "string" ? providerMessage.replace(/[\\r\\n\\t]+/g, " ").slice(0, 180) : "";
      throw error;
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

function publicError(error) {
  if (error && error.name === "AbortError") return "Provider request timed out";
  const status = error && Number.isInteger(error.status) ? " (HTTP " + error.status + ")" : "";
  const detail = error && error.providerMessage ? ": " + error.providerMessage : "";
  if (error && error.status === 429) return "Provider rate limit reached" + status + detail;
  if (error && error.status === 401) return "Provider rejected the configured API key" + status + detail;
  if (error && error.status === 403) return "Provider denied this request or the account quota was reached" + status + detail;
  if (error && error.status === 404) return "No matching record found" + status;
  if (error && error.status) return "Provider request failed" + status + detail;
  return "Provider request failed. Check provider connectivity and configuration.";
}

async function abuseIpdb(indicator, env) {
  if (!env.ABUSEIPDB_API_KEY || !indicator.isIp) return null;
  const url = new URL("https://api.abuseipdb.com/api/v2/check");
  url.searchParams.set("ipAddress", indicator.value);
  url.searchParams.set("maxAgeInDays", "90");
  const body = await fetchJson(url, { headers: { Key: env.ABUSEIPDB_API_KEY } });
  const d = body.data || {};
  return {
    ipAddress: d.ipAddress,
    isPublic: d.isPublic,
    abuseConfidenceScore: d.abuseConfidenceScore,
    countryCode: d.countryCode,
    usageType: d.usageType,
    isp: d.isp,
    domain: d.domain,
    isTor: d.isTor,
    totalReports: d.totalReports,
    lastReportedAt: d.lastReportedAt
  };
}

async function otx(indicator, env) {
  // OTX indicator endpoints support IPs, domains and file hashes, not CVE IDs.
  // CVE enrichment is handled by NVD; skip OTX rather than issuing a malformed domain lookup.
  if (indicator.isCve || !env.OTX_API_KEY) return null;
  const pathType = indicator.type === "IPv4" || indicator.type === "IPv6" ? indicator.type : indicator.type === "file" ? "file" : "domain";
  const url = "https://otx.alienvault.com/api/v1/indicators/" + pathType + "/" + encodeURIComponent(indicator.value) + "/general";
  const body = await fetchJson(url, { headers: { "X-OTX-API-KEY": env.OTX_API_KEY } });
  const pulses = body.pulse_info || {};
  return {
    indicator: body.indicator || indicator.value,
    type: body.type || pathType,
    reputation: body.reputation,
    pulseCount: pulses.count || 0,
    pulses: (pulses.pulses || []).slice(0, 10).map(p => ({
      name: p.name,
      description: p.description,
      created: p.created,
      modified: p.modified,
      tags: Array.isArray(p.tags) ? p.tags.slice(0, 20) : []
    }))
  };
}

async function nvd(indicator, env) {
  if (!indicator.isCve) return null;
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("cveId", indicator.value);
  const headers = env.NVD_API_KEY ? { apiKey: env.NVD_API_KEY } : {};
  const body = await fetchJson(url, { headers });
  return {
    totalResults: body.totalResults || 0,
    vulnerabilities: (body.vulnerabilities || []).slice(0, 5).map(item => {
      const c = item.cve || {};
      const descriptions = c.descriptions || [];
      const english = descriptions.find(d => d.lang === "en");
      const metrics = c.metrics || {};
      const cvss = (metrics.cvssMetricV40 || metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || [])[0];
      const score = cvss && (cvss.cvssData || {});
      return {
        id: c.id,
        published: c.published,
        lastModified: c.lastModified,
        vulnStatus: c.vulnStatus,
        description: english ? english.value : "",
        cvssVersion: score && score.version,
        baseScore: score && score.baseScore,
        baseSeverity: score && score.baseSeverity
      };
    })
  };
}

async function urlscan(indicator, env) {
  if (!env.URLSCAN_API_KEY || !(indicator.isDomain || indicator.isIp)) return null;
  const query = indicator.isIp ? "ip:" + indicator.value : "domain:" + indicator.value;
  const url = new URL("https://urlscan.io/api/v1/search/");
  url.searchParams.set("q", query);
  url.searchParams.set("size", "5");
  const body = await fetchJson(url, { headers: { "api-key": env.URLSCAN_API_KEY } });
  return {
    total: body.total || 0,
    results: (body.results || []).slice(0, 5).map(item => ({
      task: {
        uuid: item.task && item.task.uuid,
        time: item.task && item.task.time,
        url: item.task && item.task.url,
        visibility: item.task && item.task.visibility
      },
      page: {
        domain: item.page && item.page.domain,
        ip: item.page && item.page.ip,
        country: item.page && item.page.country,
        title: item.page && item.page.title
      },
      verdicts: item.verdicts ? {
        overall: item.verdicts.overall,
        urlscan: item.verdicts.urlscan
      } : undefined
    }))
  };
}


async function virusTotal(indicator, env) {
  if (!env.VIRUSTOTAL_API_KEY) return null;
  if (indicator.isCve) return null;
  const resource = indicator.isIp ? "ip_addresses" : indicator.isHash ? "files" : "domains";
  const url = "https://www.virustotal.com/api/v3/" + resource + "/" + encodeURIComponent(indicator.value);
  const body = await fetchJson(url, { headers: { "x-apikey": env.VIRUSTOTAL_API_KEY } });
  const d = body.data && body.data.attributes ? body.data.attributes : {};
  const stats = d.last_analysis_stats || {};
  return {
    id: body.data && body.data.id,
    type: body.data && body.data.type,
    reputation: d.reputation,
    lastAnalysisDate: d.last_analysis_date,
    lastAnalysisStats: {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      timeout: stats.timeout || 0
    },
    tags: Array.isArray(d.tags) ? d.tags.slice(0, 20) : [],
    popularThreatClassification: d.popular_threat_classification ? {
      suggestedThreatLabel: d.popular_threat_classification.suggested_threat_label
    } : undefined
  };
}

async function hybridAnalysis(indicator, env) {
  // Falcon Sandbox hash search is read-only. No file/URL submission is performed.
  if (!env.HYBRID_ANALYSIS_API_KEY || !indicator.isHash) return null;
  const url = "https://www.hybrid-analysis.com/api/v2/search/hash";
  const body = await fetchJson(url, {
    method: "POST",
    headers: {
      "api-key": env.HYBRID_ANALYSIS_API_KEY,
      "user-agent": "PrivacySkillVault",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({ hash: indicator.value }).toString()
  });
  const rows = Array.isArray(body) ? body : (Array.isArray(body.data) ? body.data : body.data ? [body.data] : []);
  return {
    total: rows.length,
    reports: rows.slice(0, 5).map(row => ({
      sha256: row.sha256,
      sha1: row.sha1,
      md5: row.md5,
      verdict: row.verdict,
      threatScore: row.threat_score,
      avDetect: row.av_detect,
      environmentDescription: row.environment_description,
      analysisStartTime: row.analysis_start_time,
      reportId: row.id || row.job_id
    }))
  };
}

async function handler(req, res) {
  const origin = req.headers && req.headers.origin;
  setHeaders(res, origin);
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json(res, 403, { error: "Origin not allowed" });
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return json(res, 405, { error: "Method not allowed" });
  }
  if (isRateLimited(req)) return json(res, 429, { error: "PSV lookup rate limit reached. Try again in one minute." });

  const raw = typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});
  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) return json(res, 413, { error: "Request too large" });
  let body;
  try { body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {}); }
  catch (_) { return json(res, 400, { error: "Invalid JSON body" }); }
  const indicator = normalizeIndicator(body.indicator);
  if (!indicator) return json(res, 400, { error: "Enter one valid public IP address, domain, file hash, or CVE ID." });

  const tasks = [
    ["abuseipdb", () => abuseIpdb(indicator, process.env)],
    ["otx", () => otx(indicator, process.env)],
    ["nvd", () => nvd(indicator, process.env)],
    ["urlscan", () => urlscan(indicator, process.env)],
    ["virustotal", () => virusTotal(indicator, process.env)],
    ["hybridAnalysis", () => hybridAnalysis(indicator, process.env)]
  ];
  const settled = await Promise.allSettled(tasks.map(([, run]) => run()));
  const results = {};
  const providerApplicability = {
    abuseipdb: { applicable: indicator.isIp, configured: Boolean(process.env.ABUSEIPDB_API_KEY) },
    otx: { applicable: !indicator.isCve, configured: Boolean(process.env.OTX_API_KEY) },
    nvd: { applicable: Boolean(indicator.isCve), configured: true },
    urlscan: { applicable: Boolean(indicator.isDomain || indicator.isIp), configured: Boolean(process.env.URLSCAN_API_KEY) },
    virustotal: { applicable: !indicator.isCve, configured: Boolean(process.env.VIRUSTOTAL_API_KEY) },
    hybridAnalysis: { applicable: Boolean(indicator.isHash), configured: Boolean(process.env.HYBRID_ANALYSIS_API_KEY) }
  };
  tasks.forEach(([name], index) => {
    const item = settled[index], capability = providerApplicability[name];
    results[name] = item.status === "fulfilled"
      ? item.value === null
        ? { status: !capability.applicable ? "not_applicable" : "not_configured", data: null }
        : { status: "ok", data: item.value }
      : { status: "error", message: publicError(item.reason) };
  });
  return json(res, 200, {
    indicator: { value: indicator.value, type: indicator.type },
    results,
    note: "Threat-intelligence records are contextual evidence, not a definitive malicious/benign verdict."
  });
}

module.exports = handler;
module.exports.normalizeIndicator = normalizeIndicator;
module.exports.publicError = publicError;
module.exports.isRateLimited = isRateLimited;
module.exports.virusTotal = virusTotal;
module.exports.hybridAnalysis = hybridAnalysis;

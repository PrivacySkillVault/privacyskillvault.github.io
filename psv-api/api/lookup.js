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

function providerResult(item, capability) {
  if (item.status === "fulfilled") {
    return item.value === null
      ? { status: !capability.applicable ? "not_applicable" : "not_configured", data: null }
      : { status: "ok", data: item.value };
  }
  if (item.reason && item.reason.status === 404) {
    return { status: "not_found", message: "No matching report is currently indexed for this indicator." };
  }
  return { status: "error", message: publicError(item.reason) };
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
  const returnedIndicator = String(body.indicator || "");
  if (returnedIndicator && returnedIndicator.toLowerCase() !== indicator.value.toLowerCase()) {
    throw new Error("OTX response indicator did not match the requested indicator");
  }
  const pulseInfo = body.pulse_info || {};
  const pulseCount = Number(pulseInfo.count);
  if (!Number.isInteger(pulseCount) || pulseCount < 0) {
    throw new Error("OTX returned an invalid pulse count");
  }
  const pulseRows = Array.isArray(pulseInfo.pulses) ? pulseInfo.pulses : [];
  return {
    indicator: returnedIndicator || indicator.value,
    type: body.type || pathType,
    reputation: Number.isFinite(body.reputation) ? body.reputation : undefined,
    pulseCount,
    pulseSummariesReturned: pulseRows.length,
    pulses: pulseRows.slice(0, 10).map(p => ({
      id: p.id,
      name: p.name,
      description: typeof p.description === "string" ? p.description.slice(0, 500) : "",
      created: p.created,
      modified: p.modified,
      tags: Array.isArray(p.tags) ? p.tags.slice(0, 10) : [],
      adversary: p.adversary || ""
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
  if (!env.VIRUSTOTAL_API_KEY || indicator.isCve) return null;
  const resource = indicator.isIp ? "ip_addresses" : indicator.isHash ? "files" : "domains";
  const headers = { "x-apikey": env.VIRUSTOTAL_API_KEY };
  const url = "https://www.virustotal.com/api/v3/" + resource + "/" + encodeURIComponent(indicator.value);
  const body = await fetchJson(url, { headers });
  if (!body.data || body.data.type !== (indicator.isHash ? "file" : indicator.isIp ? "ip_address" : "domain")) throw new Error("VirusTotal returned an unexpected object type");
  const d = body.data.attributes || {};
  if (indicator.isHash) {
    const candidates = [body.data.id, d.sha256, d.sha1, d.md5].filter(v => typeof v === "string");
    if (!candidates.some(v => v.toLowerCase() === indicator.value.toLowerCase())) throw new Error("VirusTotal report hash did not match the requested indicator");
    const names = ["malicious","suspicious","harmless","undetected","timeout","confirmed-timeout","failure","type-unsupported"];
    const stats = d.last_analysis_stats || {}, source = d.last_analysis_results || {};
    const derived = Object.fromEntries(names.map(n => [n,0]));
    for (const value of Object.values(source)) if (value && Object.prototype.hasOwnProperty.call(derived,value.category)) derived[value.category]++;
    if (names.some(n => Number.isInteger(stats[n])) && Object.keys(source).length) {
      const sum = obj => names.reduce((total,n) => total + (Number.isInteger(obj[n]) ? obj[n] : 0),0);
      if (sum(stats) !== sum(derived) || names.some(n => (stats[n] || 0) !== derived[n])) throw new Error("VirusTotal analysis statistics do not match its engine-level results");
    }
  }
  return {
    id: body.data.id, type: body.data.type, reputation: d.reputation, lastAnalysisDate: d.last_analysis_date,
    lastAnalysisStats: d.last_analysis_stats || {},
    file: indicator.isHash ? { meaningfulName:d.meaningful_name, names:Array.isArray(d.names)?d.names:[], size:d.size, sha256:d.sha256, sha1:d.sha1, md5:d.md5 } : undefined,
    engineResults: d.last_analysis_results && typeof d.last_analysis_results === "object" ? Object.entries(d.last_analysis_results).map(([engine,result]) => ({engine,...(result||{})})) : [],
    sandboxVerdicts: d.sandbox_verdicts && typeof d.sandbox_verdicts === "object" ? Object.entries(d.sandbox_verdicts).map(([sandbox,verdict]) => ({sandbox,...(verdict||{})})) : [],
    tags: Array.isArray(d.tags) ? d.tags : [], popularThreatClassification:d.popular_threat_classification, rawAttributes:d
  };
}

async function hybridAnalysis(indicator, env) {
  // Read-only enrichment. This integration never uploads or submits a sample.
  if (!env.HYBRID_ANALYSIS_API_KEY || !indicator.isHash) return null;
  const headers = {"api-key":env.HYBRID_ANALYSIS_API_KEY,"user-agent":"Falcon Sandbox"};
  const base = "https://www.hybrid-analysis.com/api/v2";
  let rows = [], searchError = null;
  try {
    const url = new URL(base + "/search/hash");
    url.searchParams.set("hash",indicator.value);
    const body = await fetchJson(url,{method:"GET",headers});
    rows = Array.isArray(body) ? body : (Array.isArray(body.data) ? body.data : body.data ? [body.data] : []);
  } catch(error) { searchError = publicError(error); }

  const matches = rows.filter(row => [row.sha256,row.sha1,row.md5].some(hash =>
    typeof hash === "string" && hash.toLowerCase() === indicator.value.toLowerCase()
  )).slice(0,5);

  // The website's sample page can have an overview even when /search/hash
  // returns no rows for the same SHA-256. Query the documented overview API
  // independently rather than equating an empty search response with no report.
  const sha256 = indicator.value.length === 64 ? indicator.value : null;
  let overview = null, overviewSummary = null, overviewError = null;
  if (sha256) {
    const results = await Promise.allSettled([
      fetchJson(base + "/overview/" + encodeURIComponent(sha256),{headers}),
      fetchJson(base + "/overview/" + encodeURIComponent(sha256) + "/summary",{headers})
    ]);
    if (results[0].status === "fulfilled") overview = results[0].value;
    else overviewError = publicError(results[0].reason);
    if (results[1].status === "fulfilled") overviewSummary = results[1].value;
    else if (!overviewError) overviewError = publicError(results[1].reason);
  }

  const reports = await Promise.all(matches.map(async row => {
    const id = row.id || row.job_id;
    const detail = {overview,overviewSummary}, detailErrors = {};
    const requests = [];
    if (id) {
      requests.push(["summary","/report/"+encodeURIComponent(id)+"/summary"]);
      requests.push(["fullReport","/report/"+encodeURIComponent(id)+"/report/json"]);
    } else if (sha256 && row.environment_id) {
      const reportKey = sha256 + ":" + row.environment_id;
      requests.push(["summary","/report/"+encodeURIComponent(reportKey)+"/summary"]);
      requests.push(["fullReport","/report/"+encodeURIComponent(reportKey)+"/report/json"]);
    }
    await Promise.all(requests.map(async ([key,path]) => {
      try { detail[key] = await fetchJson(base+path,{headers}); }
      catch(error) { detailErrors[key] = publicError(error); }
    }));
    return {searchResult:row,reportId:id||null,sha256,detail,detailErrors,reportUrl:"https://www.hybrid-analysis.com/sample/"+encodeURIComponent(sha256)};
  }));

  if (!reports.length && overview) {
    const returnedHash = overview.sha256 || (overview.sample && overview.sample.sha256);
    if (returnedHash && returnedHash.toLowerCase() !== indicator.value.toLowerCase()) {
      throw new Error("Hybrid Analysis overview hash did not match the requested indicator");
    }
    const row = overviewSummary || overview;
    const id = row.job_id || row.id || overview.job_id || null;
    const detail = {overview,overviewSummary};
    const detailErrors = {};
    if (id) {
      for (const [key,path] of [["summary","/report/"+encodeURIComponent(id)+"/summary"],["fullReport","/report/"+encodeURIComponent(id)+"/report/json"]]) {
        try { detail[key] = await fetchJson(base+path,{headers}); }
        catch(error) { detailErrors[key] = publicError(error); }
      }
    }
    reports.push({
      searchResult:row,reportId:id,sha256,
      detail,detailErrors,
      reportUrl:"https://www.hybrid-analysis.com/sample/"+encodeURIComponent(sha256),
      source:"overview_fallback"
    });
  }

  return {
    total:reports.length,reports,searchError,overviewError,
    lookupStatus:reports.length ? "report_found" : (searchError || overviewError ? "lookup_incomplete" : "no_report_found"),
    detailCoverage:"The SHA-256 overview is queried independently of hash search. Full JSON report downloads require the API key's default access level."
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
    results[name] = providerResult(settled[index], providerApplicability[name]);
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
module.exports.providerResult = providerResult;
module.exports.isRateLimited = isRateLimited;
module.exports.virusTotal = virusTotal;
module.exports.otx = otx;
module.exports.hybridAnalysis = hybridAnalysis;

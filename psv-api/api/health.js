"use strict";

const ALLOWED_ORIGINS = new Set([
  "https://privacyskillvault.com",
  "https://www.privacyskillvault.com"
]);

function buildHealthPayload(env = process.env) {
  return {
    status: "ok",
    service: "privacy-skill-vault-api",
    version: "1.0.0",
    integrations: {
      abuseipdb: Boolean(env.ABUSEIPDB_API_KEY),
      nvd: true,
      otx: Boolean(env.OTX_API_KEY),
      urlscan: Boolean(env.URLSCAN_API_KEY),
      virustotal: Boolean(env.VIRUSTOTAL_API_KEY),
      anyrun: Boolean(env.ANYRUN_API_KEY),
      hybridAnalysis: Boolean(env.HYBRID_ANALYSIS_API_KEY)
    }
  };
}

function applySecurityHeaders(res, origin) {
  res.setHeader("Vary", "Origin");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Max-Age", "600");
  }
}

function handler(req, res) {
  const origin = req.headers && req.headers.origin;
  applySecurityHeaders(res, origin);

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: "Origin not allowed" });
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
    return res.status(405).json({ error: "Method not allowed" });
  }

  return res.status(200).json(buildHealthPayload());
}

module.exports = handler;
module.exports.buildHealthPayload = buildHealthPayload;
module.exports.applySecurityHeaders = applySecurityHeaders;

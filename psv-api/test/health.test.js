"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const healthHandler = require("../api/health");

test("health payload reports configured integrations without exposing credentials", () => {
  const payload = healthHandler.buildHealthPayload({
    ABUSEIPDB_API_KEY: "secret-value",
    NVD_API_KEY: "",
    OTX_API_KEY: ""
  });

  assert.equal(payload.status, "ok");
  assert.equal(payload.integrations.abuseipdb, true);
  assert.equal(payload.integrations.nvd, true);
  assert.equal(payload.integrations.otx, false);
  assert.equal(JSON.stringify(payload).includes("secret-value"), false);
});

test("health payload marks integrations unavailable when secrets are absent", () => {
  const payload = healthHandler.buildHealthPayload({});
  assert.equal(payload.integrations.abuseipdb, false);
  assert.equal(payload.integrations.urlscan, false);
  assert.equal(payload.integrations.virustotal, false);
});

test("security headers only grant CORS to the production site", () => {
  const headers = {};
  const res = { setHeader: (name, value) => { headers[name] = value; } };
  healthHandler.applySecurityHeaders(res, "https://privacyskillvault.com");
  assert.equal(headers["Access-Control-Allow-Origin"], "https://privacyskillvault.com");
  assert.equal(headers["Cache-Control"], "no-store");

  const denied = {};
  healthHandler.applySecurityHeaders({ setHeader: (name, value) => { denied[name] = value; } }, "https://attacker.example");
  assert.equal(denied["Access-Control-Allow-Origin"], undefined);
});

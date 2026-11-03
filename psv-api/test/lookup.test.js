"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const lookup = require("../api/lookup");

test("normalizes public IPs, domains, CVEs and hashes", () => {
  assert.deepEqual(lookup.normalizeIndicator("8.8.8.8"), { value: "8.8.8.8", type: "IPv4", isIp: true });
  assert.equal(lookup.normalizeIndicator("example.com").type, "domain");
  assert.equal(lookup.normalizeIndicator("CVE-2024-21412").type, "CVE");
  assert.equal(lookup.normalizeIndicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").type, "file");
});

test("rejects private, reserved, malformed and credential-bearing URLs", () => {
  for (const value of ["127.0.0.1", "10.0.0.1", "192.168.1.1", "203.0.113.8", "not a domain", "https://user:pass@example.com"]) {
    assert.equal(lookup.normalizeIndicator(value), null, value);
  }
});

test("provider errors are sanitized", () => {
  assert.equal(lookup.publicError({ status: 401 }), "Provider rejected the configured API key");
  assert.equal(lookup.publicError({ status: 429 }), "Provider rate limit reached");
  assert.equal(lookup.publicError(new Error("secret key value")), "Provider request failed");
});

test("new integrations remain safely skipped when unsupported or not configured", async () => {
  assert.equal(await lookup.virusTotal({ value: "CVE-2024-21412", isCve: true }, {}), null);
  assert.equal(await lookup.hybridAnalysis({ value: "example.com", isDomain: true }, {}), null);
});


test("provider 404 responses are reported as no indexed record, not integration errors", () => {
  assert.deepEqual(
    lookup.providerResult({ status: "rejected", reason: Object.assign(new Error("Not found"), { status: 404 }) }, { applicable: true, configured: true }),
    { status: "not_found", message: "No matching report is currently indexed for this indicator." }
  );
});

test("provider failures other than 404 remain visible as errors", () => {
  assert.deepEqual(
    lookup.providerResult({ status: "rejected", reason: Object.assign(new Error("Unauthorized"), { status: 401 }) }, { applicable: true, configured: true }),
    { status: "error", message: "Provider rejected the configured API key" }
  );
});


test("VirusTotal file lookup preserves full engine statistics and bounded file evidence", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ data: { id: "a".repeat(64), type: "file", attributes: {
      reputation: 3800,
      last_analysis_date: 1793711042,
      last_analysis_stats: { malicious: 65, suspicious: 1, harmless: 0, undetected: 2, timeout: 1, failure: 3, "type-unsupported": 4 },
      meaningful_name: "notavirus.bat",
      names: ["notavirus.bat"],
      size: 68,
      sha256: "a".repeat(64),
      sha1: "b".repeat(40),
      md5: "c".repeat(32),
      last_analysis_results: { EngineA: { category: "malicious", result: "EICAR-Test-File" } },
      sandbox_verdicts: { SandboxA: { category: "malicious", confidence: 95, malware_classification: ["eicar"] } },
      popular_threat_classification: { suggested_threat_label: "virus.eicar/test" }
    } } })
  });
  try {
    const result = await lookup.virusTotal({ value: "a".repeat(64), isHash: true }, { VIRUSTOTAL_API_KEY: "test-key" });
    assert.equal(result.file.meaningfulName, "notavirus.bat");
    assert.equal(result.file.size, 68);
    assert.equal(result.file.sha1, "b".repeat(40));
    assert.equal(result.lastAnalysisStats.malicious, 65);
    assert.equal(result.lastAnalysisStats.failure, 3);
    assert.equal(result.lastAnalysisStats["type-unsupported"], 4);
    assert.equal(result.engineResults[0].result, "EICAR-Test-File");
    assert.equal(result.sandboxVerdicts[0].malwareClassification[0], "eicar");
  } finally {
    global.fetch = originalFetch;
  }
});

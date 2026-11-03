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
      last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 0, undetected: 0, timeout: 0, failure: 0, "type-unsupported": 0 },
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
    assert.equal(result.lastAnalysisStats.malicious, 1);
    assert.equal(result.lastAnalysisStats.failure, 0);
    assert.equal(result.lastAnalysisStats["type-unsupported"], 0);
    assert.equal(result.engineResults[0].result, "EICAR-Test-File");
    assert.equal(result.sandboxVerdicts[0].malwareClassification[0], "eicar");
  } finally {
    global.fetch = originalFetch;
  }
});

test("VirusTotal rejects a report whose hash does not match the requested indicator", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ data: { id: "b".repeat(64), type: "file", attributes: { sha256: "b".repeat(64), last_analysis_stats: {} } } })
  });
  try {
    await assert.rejects(
      lookup.virusTotal({ value: "a".repeat(64), isHash: true }, { VIRUSTOTAL_API_KEY: "test-key" }),
      /hash did not match/
    );
  } finally { global.fetch = originalFetch; }
});

test("OTX pulse count is clearly separated from returned pulse summaries", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ indicator: "a".repeat(64), type: "file", pulse_info: {
      count: 50, pulses: [{ id: "pulse-1", name: "EICAR test context", description: "Not supplied", tags: ["test"] }]
    } })
  });
  try {
    const result = await lookup.otx({ value: "a".repeat(64), type: "file", isHash: true }, { OTX_API_KEY: "test-key" });
    assert.equal(result.pulseCount, 50);
    assert.equal(result.pulseSummariesReturned, 1);
    assert.equal(result.pulses[0].id, "pulse-1");
  } finally { global.fetch = originalFetch; }
});

test("VirusTotal retains every returned engine, sandbox verdict and raw attribute", async () => {
  const originalFetch = global.fetch;
  const hash = "a".repeat(64);
  const engines = Object.fromEntries(Array.from({length:24},(_,i)=>["Engine"+i,{category:"undetected",result:null,method:"blacklist",engine_update:"20261103"}]));
  const stats = {malicious:0,suspicious:0,harmless:0,undetected:24,timeout:0,"confirmed-timeout":0,failure:0,"type-unsupported":0};
  const sandboxes = Object.fromEntries(Array.from({length:7},(_,i)=>["Sandbox"+i,{category:"undetected",confidence:0,malware_classification:[]}]));
  global.fetch = async () => ({ok:true,status:200,text:async()=>JSON.stringify({data:{id:hash,type:"file",attributes:{sha256:hash,last_analysis_stats:stats,last_analysis_results:engines,sandbox_verdicts:sandboxes,magic:"PE32",signature_info:{description:"test"}}}})});
  try {
    const result = await lookup.virusTotal({value:hash,isHash:true},{VIRUSTOTAL_API_KEY:"test"});
    assert.equal(result.engineResults.length,24);
    assert.equal(result.sandboxVerdicts.length,7);
    assert.equal(result.rawAttributes.magic,"PE32");
    assert.equal(result.rawAttributes.signature_info.description,"test");
  } finally { global.fetch = originalFetch; }
});

test("Hybrid Analysis fetches detail endpoints for exact hash matches without submitting samples", async () => {
  const originalFetch = global.fetch, hash = "d".repeat(64), calls = [];
  global.fetch = async (url, options) => {
    calls.push({url:String(url),method:options.method || "GET"});
    const value = String(url).includes("/search/hash")
      ? [{sha256:hash,id:"job-123",verdict:"malicious",threat_score:90}]
      : {report_id:"job-123",summary:"full detail"};
    return {ok:true,status:200,text:async()=>JSON.stringify(value)};
  };
  try {
    const result = await lookup.hybridAnalysis({value:hash,isHash:true},{HYBRID_ANALYSIS_API_KEY:"test"});
    assert.equal(result.reports.length,1);
    assert.equal(result.reports[0].detail.summary.summary,"full detail");
    assert.ok(calls.some(c=>c.url.includes("/report/job-123/summary")));
    assert.ok(calls.some(c=>c.url.includes("/report/job-123/report/json")));
    assert.ok(calls.some(c=>c.url.includes("/overview/"+hash)));
    assert.ok(calls.every(c=>c.method==="GET"));
    assert.ok(calls.every(c=>!c.url.includes("/submit")));
  } finally { global.fetch = originalFetch; }
});

test("Hybrid Analysis excludes non-matching hash rows", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({ok:true,status:200,text:async()=>JSON.stringify([{sha256:"e".repeat(64),id:"wrong"}])});
  try {
    const result = await lookup.hybridAnalysis({value:"d".repeat(64),isHash:true},{HYBRID_ANALYSIS_API_KEY:"test"});
    assert.equal(result.total,0);
    assert.equal(result.reports.length,0);
  } finally { global.fetch = originalFetch; }
});

test("Hybrid Analysis finds a report through overview when legacy hash search is empty", async () => {
  const originalFetch = global.fetch;
  const hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
  const calls = [];
  global.fetch = async (url) => {
    const value = String(url); calls.push(value);
    if (value.includes("/search/hash")) return {ok:true,status:200,text:async()=>"[]"};
    if (value.endsWith("/overview/"+hash)) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,job_id:"ha-job-68",verdict:"malicious",threat_score:100,av_detect:"22/28"})};
    if (value.endsWith("/overview/"+hash+"/summary")) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,indicators:35})};
    if (value.includes("/report/ha-job-68/summary")) return {ok:true,status:200,text:async()=>JSON.stringify({report_id:"ha-job-68",environment:"Win10"})};
    if (value.includes("/report/ha-job-68/report/json")) return {ok:true,status:200,text:async()=>JSON.stringify({signatures:["EICAR"]})};
    throw new Error("Unexpected URL "+value);
  };
  try {
    const result = await lookup.hybridAnalysis({value:hash,isHash:true},{HYBRID_ANALYSIS_API_KEY:"test-key"});
    assert.equal(result.total,1);
    assert.equal(result.reports[0].source,"overview_fallback");
    assert.equal(result.reports[0].searchResult.verdict,"malicious");
    assert.equal(result.reports[0].detail.overviewSummary.indicators,35);
    assert.equal(result.reports[0].detail.fullReport.signatures[0],"EICAR");
    assert.ok(calls.every(url=>!url.includes("/submit")));
  } finally { global.fetch = originalFetch; }
});


test("Hybrid Analysis discovers report IDs from the exact-hash overview summary", async () => {
  const originalFetch = global.fetch;
  const hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
  const calls = [];
  const reportIds = ["ha-report-1", "ha-report-2"];
  global.fetch = async url => {
    const value = String(url); calls.push(value);
    if (value.includes("/search/hash")) return {ok:true,status:200,text:async()=>"[]"};
    if (value.endsWith("/overview/"+hash)) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,verdict:"malicious",threat_score:100})};
    if (value.endsWith("/overview/"+hash+"/summary")) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,reports:reportIds,verdict:"malicious",threat_score:100,indicators:35,threat_score:100})};
    if (value.includes("/report/ha-report-1/summary")) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,job_id:"ha-report-1",environment_description:"Windows 10",verdict:"malicious"})};
    if (value.includes("/report/ha-report-2/summary")) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,job_id:"ha-report-2",environment_description:"Windows 11",verdict:"malicious"})};
    if (value.includes("/report/ha-report-1/report/json")) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,signatures:[{name:"EICAR"}]})};
    if (value.includes("/report/ha-report-2/report/json")) return {ok:true,status:200,text:async()=>JSON.stringify({sha256:hash,signatures:[{name:"EICAR"}]})};
    throw new Error("Unexpected URL "+value);
  };
  try {
    const result = await lookup.hybridAnalysis({value:hash,isHash:true},{HYBRID_ANALYSIS_API_KEY:"test-key"});
    assert.equal(result.reportIdsFound,2);
    assert.equal(result.total,2);
    assert.deepEqual(result.reports.map(r=>r.reportId),reportIds);
    assert.equal(result.reports[0].searchResult.environment_description,"Windows 10");
    assert.ok(calls.every(url=>!url.includes("/submit")));
  } finally { global.fetch = originalFetch; }
});

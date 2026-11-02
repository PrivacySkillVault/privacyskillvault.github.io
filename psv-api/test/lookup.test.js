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

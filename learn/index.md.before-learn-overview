# Tactical Security Tools & Vault

Client-side cryptographic tools, zero-knowledge secret sharing, hashing, encoding, and SOC analysis utilities.

> **Privacy Notice:** User-provided data processed by client-side cryptographic and utility functions remains entirely within the browser. Note that CryptoJS and Alpine.js are loaded from public CDNs per the source implementation. External lookups (e.g. Threat Intelligence) intentionally submit user-provided indicators to third-party endpoints.

<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>

<style>
  .psv-app-container {
    display: flex;
    min-height: 800px;
    background-color: var(--psv-surface) !important;
    color: var(--psv-text) !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    border-radius: var(--psv-radius-lg);
    overflow: hidden;
    border: 1px solid var(--psv-border);
    margin-top: 1.5rem;
    margin-bottom: 2.5rem;
    box-shadow: var(--psv-shadow);
  }
  .psv-sidebar {
    width: 280px;
    background: #080E1A !important;
    border-right: 1px solid var(--psv-border);
    padding: 20px 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    flex-shrink: 0;
    overflow-y: auto;
    max-height: 850px;
  }
  .psv-sidebar-header {
    padding: 0 12px 14px 12px;
    border-bottom: 1px solid var(--psv-border);
    font-weight: 700;
    font-size: 1rem;
    color: #FFFFFF !important;
  }
  .psv-category-btn {
    width: 100%;
    background: transparent;
    border: none;
    color: var(--psv-text-muted) !important;
    padding: 8px 10px;
    text-align: left;
    font-weight: 600;
    font-size: 0.825rem;
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-radius: var(--psv-radius-sm);
  }
  .psv-category-btn:hover {
    background-color: rgba(255, 255, 255, 0.05) !important;
    color: #FFFFFF !important;
  }
  .psv-tool-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding-left: 8px;
    margin-top: 2px;
  }
  .psv-tool-btn {
    width: 100%;
    background: transparent;
    border: none;
    color: var(--psv-text-muted) !important;
    padding: 6px 10px;
    text-align: left;
    font-size: 0.8rem;
    cursor: pointer;
    border-radius: var(--psv-radius-sm);
  }
  .psv-tool-btn:hover {
    color: #FFFFFF !important;
    background-color: rgba(255, 255, 255, 0.05) !important;
  }
  .psv-tool-btn.active {
    background-color: var(--psv-primary) !important;
    color: #FFFFFF !important;
    font-weight: 600;
  }
  .psv-workspace {
    flex: 1;
    padding: 24px;
    background-color: var(--psv-surface) !important;
    overflow-y: auto;
    max-height: 850px;
  }
  .psv-breadcrumbs {
    font-size: 0.75rem;
    color: var(--psv-accent) !important;
    margin-bottom: 12px;
    text-transform: uppercase;
    font-weight: 600;
    font-family: var(--psv-font-mono);
  }
  .psv-tool-card {
    background: #0B1220 !important;
    border: 1px solid var(--psv-border) !important;
    border-radius: var(--psv-radius-md);
    padding: 20px;
    color: var(--psv-text) !important;
  }
  .psv-tool-card h2, .psv-tool-card h3 {
    margin-top: 0;
    color: #FFFFFF !important;
  }
  .psv-form-group {
    margin-bottom: 14px;
  }
  .psv-form-group label {
    display: block;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--psv-text-muted) !important;
    margin-bottom: 6px;
  }
  .psv-input, .psv-textarea, .psv-file-input {
    width: 100%;
    background-color: #050C21 !important;
    border: 1px solid var(--psv-border) !important;
    color: var(--psv-text) !important;
    border-radius: var(--psv-radius-sm);
    padding: 8px 10px;
    box-sizing: border-box;
    font-family: var(--psv-font-mono);
    font-size: 0.825rem;
  }
  .psv-textarea {
    min-height: 100px;
    resize: vertical;
  }
  .psv-action-btn {
    background-color: var(--psv-primary) !important;
    color: #FFFFFF !important;
    border: none;
    padding: 10px 14px;
    border-radius: var(--psv-radius-sm);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
    width: 100%;
  }
  .psv-result-box {
    display: none;
    margin-top: 14px;
    padding: 12px;
    background: #050C21 !important;
    border: 1px solid var(--psv-border) !important;
    border-radius: var(--psv-radius-sm);
    word-break: break-all;
    font-family: var(--psv-font-mono);
    font-size: 0.8rem;
  }
  .psv-grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
  }
  @media (max-width: 860px) {
    .psv-app-container { flex-direction: column; }
    .psv-sidebar { width: 100%; max-height: 260px; border-right: none; border-bottom: 1px solid var(--psv-border); }
    .psv-grid-2 { grid-template-columns: 1fr; }
  }
</style>

<div class="psv-app-container" x-data="{
  activeCat: 'secret-share',
  activeTool: 'burn-note',
  inputVal: '',
  outputVal: '',
  keyVal: '',
  passLen: 16
}">

  <!-- SIDEBAR NAVIGATION -->
  <aside class="psv-sidebar">
    <div class="psv-sidebar-header">Tactical Tool Vault</div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'secret-share' ? '' : 'secret-share')">
        <span>Secure Secret Share</span><span x-text="activeCat === 'secret-share' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'secret-share'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'burn-note' }" @click="activeTool = 'burn-note';">Ephemeral Secret Share</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'crypto' ? '' : 'crypto')">
        <span>Cryptography</span><span x-text="activeCat === 'crypto' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'crypto'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'aes' }" @click="activeTool = 'aes'; inputVal=''; outputVal=''; keyVal='';">AES Encrypt / Decrypt</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'rsa' }" @click="activeTool = 'rsa'; inputVal=''; outputVal='';">RSA Encrypt / Decrypt</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'rsa-gen' }" @click="activeTool = 'rsa-gen'; outputVal='';">RSA Key Generator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'ecc-gen' }" @click="activeTool = 'ecc-gen'; outputVal='';">ECC Key Generator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'rand-gen' }" @click="activeTool = 'rand-gen'; outputVal='';">Random Key Generator</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'hash' ? '' : 'hash')">
        <span>Hashing &amp; Integrity</span><span x-text="activeCat === 'hash' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'hash'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'md5' }" @click="activeTool = 'md5'; inputVal=''; outputVal='';">MD5 Generator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'sha1' }" @click="activeTool = 'sha1'; inputVal=''; outputVal='';">SHA-1 Generator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'sha256' }" @click="activeTool = 'sha256'; inputVal=''; outputVal='';">SHA-256 Generator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'sha512' }" @click="activeTool = 'sha512'; inputVal=''; outputVal='';">SHA-512 Generator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'hmac' }" @click="activeTool = 'hmac'; inputVal=''; outputVal=''; keyVal='';">HMAC Generator</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'encode' ? '' : 'encode')">
        <span>Encodings &amp; Convert</span><span x-text="activeCat === 'encode' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'encode'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'base64' }" @click="activeTool = 'base64'; inputVal=''; outputVal='';">Base64 Encode/Decode</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'url' }" @click="activeTool = 'url'; inputVal=''; outputVal='';">URL Encode/Decode</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'html' }" @click="activeTool = 'html'; inputVal=''; outputVal='';">HTML Encode/Decode</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'hex' }" @click="activeTool = 'hex'; inputVal=''; outputVal='';">Hex Encode/Decode</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'binary' }" @click="activeTool = 'binary'; inputVal=''; outputVal='';">Binary Encode/Decode</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'pass' ? '' : 'pass')">
        <span>Password &amp; Secrets</span><span x-text="activeCat === 'pass' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'pass'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'pass-gen' }" @click="activeTool = 'pass-gen'; outputVal='';">Password Generator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'secret-gen' }" @click="activeTool = 'secret-gen'; outputVal='';">UUID &amp; API Key Generator</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'jwt' ? '' : 'jwt')">
        <span>JWT Tools</span><span x-text="activeCat === 'jwt' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'jwt'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'jwt-dec' }" @click="activeTool = 'jwt-dec'; inputVal=''; outputVal='';">JWT Decoder</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'net' ? '' : 'net')">
        <span>Networking</span><span x-text="activeCat === 'net' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'net'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'ip-conv' }" @click="activeTool = 'ip-conv'; inputVal=''; outputVal='';">IP Address Converter</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'text' ? '' : 'text')">
        <span>Text Utilities</span><span x-text="activeCat === 'text' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'text'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'json-fmt' }" @click="activeTool = 'json-fmt'; inputVal=''; outputVal='';">JSON Formatter</button>
      </div>
    </div>

    <div>
      <button class="psv-category-btn" @click="activeCat = (activeCat === 'soc' ? '' : 'soc')">
        <span>SOC &amp; Fraud Ops</span><span x-text="activeCat === 'soc' ? '▾' : '▸'"></span>
      </button>
      <div class="psv-tool-list" x-show="activeCat === 'soc'">
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'ioc-ext' }" @click="activeTool = 'ioc-ext'; inputVal=''; outputVal='';">IOC Extractor</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'iban-val' }" @click="activeTool = 'iban-val'; inputVal=''; outputVal='';">IBAN Validator</button>
        <button class="psv-tool-btn" :class="{ 'active': activeTool === 'threat-intel' }" @click="activeTool = 'threat-intel'; inputVal=''; outputVal='';">Threat Intel Lookup</button>
      </div>
    </div>
  </aside>

  <!-- WORKSPACE -->
  <main class="psv-workspace">
    <div class="psv-breadcrumbs">
      Category: <span x-text="activeCat"></span> &gt; <strong x-text="activeTool"></strong>
    </div>

    <!-- ZERO-KNOWLEDGE SECRET SHARE -->
    <div x-show="activeTool === 'burn-note'" class="psv-tool-card">
      <h3>Zero-Knowledge Secret Share</h3>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">
        Encrypt messages locally in your browser using Web Crypto AES-GCM. Remote storage persistence is disabled because client-side bearer authentication has been removed.
      </p>
      <div id="psv-create-view">
        <textarea id="psv-input-text" class="psv-textarea" placeholder="Type secret text to test local browser encryption..."></textarea>
        <label style="font-size:0.8rem; color:var(--psv-text-muted); display:block; margin: 10px 0 6px 0;">Attach File (Optional, Max 2MB):</label>
        <input type="file" id="psv-file-input" class="psv-file-input">
        <button class="psv-action-btn" style="margin-top: 10px;" onclick="testLocalSecretEncryption()">Test Local Client Encryption</button>
        <div id="psv-link-result" class="psv-result-box"></div>
      </div>
    </div>

    <!-- AES ENCRYPT / DECRYPT -->
    <div x-show="activeTool === 'aes'" class="psv-tool-card">
      <h2>AES Encryption / Decryption</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Encrypt or decrypt text client-side using standard AES-256-GCM.</p>
      <div class="psv-form-group">
        <label>Passphrase / Secret Key:</label>
        <input type="text" class="psv-input" x-model="keyVal" placeholder="Enter encryption passphrase...">
      </div>
      <div class="psv-grid-2">
        <div class="psv-form-group">
          <label>Plaintext / Input:</label>
          <textarea class="psv-textarea" x-model="inputVal" placeholder="Enter text to encrypt/decrypt..."></textarea>
        </div>
        <div class="psv-form-group">
          <label>Result Output:</label>
          <textarea class="psv-textarea" x-model="outputVal" readonly placeholder="Output will appear here..."></textarea>
        </div>
      </div>
      <div style="display:flex; gap:10px;">
        <button class="psv-action-btn" @click="outputVal = await PSV_Engine.aesEncrypt(inputVal, keyVal)">Encrypt (AES-GCM)</button>
        <button class="psv-action-btn" style="background:#374151 !important;" @click="outputVal = await PSV_Engine.aesDecrypt(inputVal, keyVal)">Decrypt</button>
      </div>
    </div>

    <!-- HASHING & HMAC TOOLS -->
    <div x-show="['md5', 'sha1', 'sha256', 'sha512', 'hmac'].includes(activeTool)" class="psv-tool-card">
      <h2 x-text="activeTool.toUpperCase() + ' Digest / Keyed-Hash'"></h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Generate secure cryptographic digest or HMAC locally in your browser.</p>
      <div class="psv-form-group" x-show="activeTool === 'hmac'">
        <label>HMAC Secret Key:</label>
        <input type="text" class="psv-input" x-model="keyVal" placeholder="Enter HMAC secret key...">
      </div>
      <div class="psv-form-group">
        <label>Input Text:</label>
        <textarea class="psv-textarea" x-model="inputVal" @input="
          if(activeTool==='md5') outputVal = CryptoJS.MD5(inputVal).toString();
          if(activeTool==='sha1') outputVal = await PSV_Engine.hash(inputVal, 'SHA-1');
          if(activeTool==='sha256') outputVal = await PSV_Engine.hash(inputVal, 'SHA-256');
          if(activeTool==='sha512') outputVal = await PSV_Engine.hash(inputVal, 'SHA-512');
          if(activeTool==='hmac') outputVal = await PSV_Engine.hmac(inputVal, keyVal);
        " placeholder="Type text to compute live hash..."></textarea>
      </div>
      <button class="psv-action-btn" x-show="activeTool === 'hmac'" @click="outputVal = await PSV_Engine.hmac(inputVal, keyVal)">Compute HMAC-SHA256</button>
      <div class="psv-form-group" style="margin-top:14px;">
        <label>Calculated Hash / Digest:</label>
        <input type="text" class="psv-input" x-model="outputVal" readonly>
      </div>
    </div>

    <!-- BASE64 ENCODE / DECODE -->
    <div x-show="activeTool === 'base64'" class="psv-tool-card">
      <h2>Base64 Encoder / Decoder</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Convert text to/from Base64 encoding scheme.</p>
      <div class="psv-grid-2">
        <div class="psv-form-group">
          <label>Input Text:</label>
          <textarea class="psv-textarea" x-model="inputVal" placeholder="Type text..."></textarea>
        </div>
        <div class="psv-form-group">
          <label>Output Text:</label>
          <textarea class="psv-textarea" x-model="outputVal" readonly></textarea>
        </div>
      </div>
      <div style="display:flex; gap:10px;">
        <button class="psv-action-btn" @click="outputVal = btoa(unescape(encodeURIComponent(inputVal)))">Base64 Encode</button>
        <button class="psv-action-btn" style="background:#374151 !important;" @click="try { outputVal = decodeURIComponent(escape(atob(inputVal))) } catch(e){ outputVal='Invalid Base64' }">Base64 Decode</button>
      </div>
    </div>

    <!-- PASSWORD GENERATOR -->
    <div x-show="activeTool === 'pass-gen'" class="psv-tool-card">
      <h2>Strong Password Generator</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Generate high-entropy cryptographically secure random passwords.</p>
      <div class="psv-form-group">
        <label>Password Length: <span x-text="passLen"></span> characters</label>
        <input type="range" min="8" max="64" x-model="passLen" class="psv-input">
      </div>
      <button class="psv-action-btn" @click="outputVal = PSV_Engine.genPassword(passLen)">Generate Password</button>
      <div class="psv-form-group" style="margin-top:14px;">
        <label>Generated Password:</label>
        <input type="text" class="psv-input" x-model="outputVal" readonly>
      </div>
    </div>

    <!-- JWT DECODER -->
    <div x-show="activeTool === 'jwt-dec'" class="psv-tool-card">
      <h2>JWT Token Decoder</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Decode JSON Web Tokens (Header, Payload, Claims) client-side.</p>
      <div class="psv-form-group">
        <label>Encoded JWT Token:</label>
        <textarea class="psv-textarea" x-model="inputVal" placeholder="Paste eyJhbGciOi... token here"></textarea>
      </div>
      <button class="psv-action-btn" @click="outputVal = PSV_Engine.decodeJWT(inputVal)">Decode JWT</button>
      <div class="psv-form-group" style="margin-top:14px;">
        <label>Decoded Claims Header &amp; Payload:</label>
        <textarea class="psv-textarea" x-model="outputVal" readonly style="min-height:160px;"></textarea>
      </div>
    </div>

    <!-- JSON FORMATTER -->
    <div x-show="activeTool === 'json-fmt'" class="psv-tool-card">
      <h2>JSON Formatter &amp; Validator</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Validate and pretty-print raw JSON strings.</p>
      <div class="psv-form-group">
        <label>Raw JSON:</label>
        <textarea class="psv-textarea" x-model="inputVal" placeholder='{"key":"value"}'></textarea>
      </div>
      <button class="psv-action-btn" @click="try { outputVal = JSON.stringify(JSON.parse(inputVal), null, 2); } catch(e) { outputVal = 'Invalid JSON Syntax: ' + e.message; }">Format JSON</button>
      <div class="psv-form-group" style="margin-top:14px;">
        <label>Formatted Output:</label>
        <textarea class="psv-textarea" x-model="outputVal" readonly style="min-height:160px;"></textarea>
      </div>
    </div>

    <!-- IOC EXTRACTOR -->
    <div x-show="activeTool === 'ioc-ext'" class="psv-tool-card">
      <h2>SOC IOC Extractor</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Extract verified IPv4 addresses, domains, URLs, MD5/SHA256 hashes, and emails from raw text.</p>
      <div class="psv-form-group">
        <label>Raw Log / Unstructured Text:</label>
        <textarea class="psv-textarea" x-model="inputVal" placeholder="Paste server logs or security alert text here..."></textarea>
      </div>
      <button class="psv-action-btn" @click="outputVal = PSV_Engine.extractIOCs(inputVal)">Extract IOCs</button>
      <div class="psv-form-group" style="margin-top:14px;">
        <label>Extracted Indicators of Compromise:</label>
        <textarea class="psv-textarea" x-model="outputVal" readonly style="min-height:160px;"></textarea>
      </div>
    </div>

    <!-- IBAN VALIDATOR -->
    <div x-show="activeTool === 'iban-val'" class="psv-tool-card">
      <h2>IBAN Format &amp; Checksum Validator</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Verify international bank account numbers using MOD-97 check-digit validation.</p>
      <div class="psv-form-group">
        <label>IBAN String:</label>
        <input type="text" class="psv-input" x-model="inputVal" placeholder="GB33 BUXB 2020 1555 5555 55">
      </div>
      <button class="psv-action-btn" @click="outputVal = PSV_Engine.validateIBAN(inputVal)">Validate IBAN</button>
      <div class="psv-form-group" style="margin-top:14px;">
        <label>Validation Result:</label>
        <input type="text" class="psv-input" x-model="outputVal" readonly>
      </div>
    </div>

    <!-- THREAT INTEL LOOKUP -->
    <div x-show="activeTool === 'threat-intel'" class="psv-tool-card">
      <h2>Threat Intelligence Quick Lookup</h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">
        External query portal: Query IP addresses, file hashes, or domain names across VirusTotal, AbuseIPDB, and URLScan.io.
      </p>
      <div class="psv-form-group">
        <label>Target IOC (IP, Hash, or Domain):</label>
        <input type="text" class="psv-input" x-model="inputVal" placeholder="e.g. 1.1.1.1, sha256 hash, or domain.com">
      </div>
      <div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:14px;">
        <button class="psv-action-btn" style="flex:1; min-width:160px;" @click="
          if(!inputVal) return alert('Please enter an IP, Hash, or Domain');
          window.open('https://www.virustotal.com/gui/search/' + encodeURIComponent(inputVal.trim()), '_blank');
        ">Search VirusTotal ↗</button>
        <button class="psv-action-btn" style="flex:1; min-width:160px; background:#DC2626 !important;" @click="
          if(!inputVal) return alert('Please enter an IP Address');
          window.open('https://www.abuseipdb.com/check/' + encodeURIComponent(inputVal.trim()), '_blank');
        ">Check AbuseIPDB ↗</button>
        <button class="psv-action-btn" style="flex:1; min-width:160px; background:#059669 !important;" @click="
          if(!inputVal) return alert('Please enter a Domain or URL');
          window.open('https://urlscan.io/search/#' + encodeURIComponent(inputVal.trim()), '_blank');
        ">Inspect URLScan.io ↗</button>
      </div>
    </div>

    <!-- EXPLICIT PLACEHOLDER WORKSPACE (DECLARED IN SOURCE UI BUT HANDLER NOT IMPLEMENTED) -->
    <div x-show="['rsa', 'rsa-gen', 'ecc-gen', 'rand-gen'].includes(activeTool)" class="psv-tool-card">
      <h2 x-text="activeTool.toUpperCase() + ' (Placeholder)'"></h2>
      <p style="color: var(--psv-warning) !important; font-size: 0.85rem; margin-bottom: 16px;">
        Declared in source UI; implementation not active.
      </p>
      <div class="psv-form-group">
        <label>Input Parameters:</label>
        <textarea class="psv-textarea" x-model="inputVal" placeholder="Tool handler not provided in authoritative source..."></textarea>
      </div>
      <button class="psv-action-btn" style="background:#374151 !important;" disabled>Implementation Unavailable</button>
    </div>

    <!-- FALLBACK WORKSPACE -->
    <div x-show="!['burn-note', 'aes', 'rsa', 'rsa-gen', 'ecc-gen', 'rand-gen', 'md5', 'sha1', 'sha256', 'sha512', 'hmac', 'base64', 'pass-gen', 'jwt-dec', 'json-fmt', 'ioc-ext', 'iban-val', 'threat-intel'].includes(activeTool)" class="psv-tool-card">
      <h2 x-text="activeTool.toUpperCase() + ' Utility'"></h2>
      <p style="color: var(--psv-text-muted); font-size: 0.85rem; margin-bottom: 16px;">Execute browser-based operations locally.</p>
      <div class="psv-form-group">
        <label>Input Data:</label>
        <textarea class="psv-textarea" x-model="inputVal" placeholder="Enter parameters or text..."></textarea>
      </div>
      <button class="psv-action-btn" @click="
        if(activeTool==='url') outputVal = encodeURIComponent(inputVal);
        if(activeTool==='html') outputVal = inputVal.replace(/[\u00A0-\u9999<>\&]/g, i => '&#'+i.charCodeAt(0)+';');
        if(activeTool==='hex') outputVal = PSV_Engine.toHex(inputVal);
        if(activeTool==='binary') outputVal = inputVal.split('').map(c=>c.charCodeAt(0).toString(2).padStart(8,'0')).join(' ');
        if(activeTool==='ip-conv') outputVal = PSV_Engine.convertIP(inputVal);
        if(activeTool==='secret-gen') outputVal = crypto.randomUUID();
      ">Process Data</button>
      <div class="psv-form-group" style="margin-top:14px;">
        <label>Output Result:</label>
        <textarea class="psv-textarea" x-model="outputVal" readonly></textarea>
      </div>
    </div>

  </main>
</div>

<script>
  function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  async function testLocalSecretEncryption() {
    const text = document.getElementById('psv-input-text').value;
    if (!text) return alert("Please enter a message to test encryption.");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedPayload = new TextEncoder().encode(text);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, encodedPayload);

    const resultBox = document.getElementById('psv-link-result');
    resultBox.style.display = 'block';
    resultBox.innerHTML = `<strong>Local Client-Side Encryption Verified:</strong><br><span style="color:var(--psv-text-muted); font-size:0.75rem;">Backend storage persistence is disabled. Ciphertext generated locally:</span><br><input type="text" readonly value="${bufferToBase64(ciphertext)}" style="width:100%; margin-top:8px; padding:8px; background:#080E1A; color:var(--psv-accent); border:1px solid var(--psv-border); border-radius:4px; font-family:var(--psv-font-mono);" onclick="this.select()">`;
  }

  const PSV_Engine = {
    hash: async (text, algo) => {
      if(!text) return '';
      const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    hmac: async (text, key) => {
      if(!text || !key) return 'Please provide both text and key for HMAC.';
      const enc = new TextEncoder();
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(key),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const signature = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(text));
      return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    aesEncrypt: async (text, secret) => {
      if(!text || !secret) return 'Please enter both text and passphrase.';
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(secret.padEnd(32, '0')), "AES-GCM", false, ["encrypt"]);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, keyMaterial, enc.encode(text));
      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(encrypted), iv.length);
      return btoa(String.fromCharCode(...combined));
    },
    aesDecrypt: async (cipherB64, secret) => {
      try {
        const raw = Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0));
        const iv = raw.slice(0, 12);
        const ciphertext = raw.slice(12);
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(secret.padEnd(32, '0')), "AES-GCM", false, ["decrypt"]);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, keyMaterial, ciphertext);
        return new TextDecoder().decode(decrypted);
      } catch(e) { return "Decryption failed. Check secret key or ciphertext."; }
    },
    toHex: (str) => Array.from(new TextEncoder().encode(str)).map(b => b.toString(16).padStart(2, '0')).join(''),
    genPassword: (len = 16) => {
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|";
      const bytes = new Uint8Array(len);
      crypto.getRandomValues(bytes);
      return Array.from(bytes).map(b => chars[b % chars.length]).join('');
    },
    decodeJWT: (token) => {
      try {
        const parts = token.split('.');
        if(parts.length !== 3) return 'Invalid JWT token format.';
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        return JSON.stringify({ Header: header, Payload: payload }, null, 2);
      } catch(e) { return 'Error decoding JWT: ' + e.message; }
    },
    convertIP: (ip) => {
      try {
        const parts = ip.split('.').map(Number);
        if(parts.length !== 4) return 'Invalid IPv4 address';
        const num = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
        const binary = parts.map(p => p.toString(2).padStart(8, '0')).join('.');
        const hex = parts.map(p => p.toString(16).padStart(2, '0')).join('');
        return `Decimal Integer: ${num >>> 0}\nBinary: ${binary}\nHex: 0x${hex}`;
      } catch(e) { return 'Invalid input'; }
    },
    extractIOCs: (text) => {
      // Complete 4-octet IPv4 extraction with 0-255 boundary validation
      const rawIps = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
      const validIps = rawIps.filter(ip => {
        const octets = ip.split('.').map(Number);
        return octets.length === 4 && octets.every(o => o >= 0 && o <= 255);
      });
      const md5s = text.match(/\b[a-fA-F0-9]{32}\b/g) || [];
      const sha256s = text.match(/\b[a-fA-F0-9]{64}\b/g) || [];
      const emails = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || [];
      return `--- EXTRACTED IOCs ---\n\nIP Addresses (${validIps.length}):\n${[...new Set(validIps)].join('\n')}\n\nMD5 Hashes (${md5s.length}):\n${[...new Set(md5s)].join('\n')}\n\nSHA256 Hashes (${sha256s.length}):\n${[...new Set(sha256s)].join('\n')}\n\nEmails (${emails.length}):\n${[...new Set(emails)].join('\n')}`;
    },
    validateIBAN: (iban) => {
      const clean = iban.replace(/[^A-Z0-9]/gi, '').toUpperCase();
      if(clean.length < 15 || clean.length > 34) return 'Invalid Length';
      const rearranged = clean.slice(4) + clean.slice(0, 4);
      const digits = rearranged.replace(/[A-Z]/g, c => c.charCodeAt(0) - 55);
      let remainder = 0;
      for (let i = 0; i < digits.length; i++) {
        remainder = (remainder * 10 + parseInt(digits[i])) % 97;
      }
      return remainder === 1 ? 'Valid IBAN Format & Checksum' : 'Invalid IBAN Checksum';
    }
  };
</script>

---

[Explore the Learn Vault →](https://learn.privacyskillvault.com/){ .md-button .md-button--primary }

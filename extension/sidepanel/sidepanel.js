// ── ScamShield AI — Side Panel Script ────────────────────────────────────────

const API = "http://127.0.0.1:8000";
let selectedFile = null;

// ── DOM refs ─────────────────────────────────────────────────────────────────
const statusDot   = document.getElementById("status-dot");
const backendWarn = document.getElementById("backend-warn");

const msgInput    = document.getElementById("msg-input");
const msgScanBtn  = document.getElementById("msg-scan-btn");
const msgClearBtn = document.getElementById("msg-clear-btn");
const msgLoading  = document.getElementById("msg-loading");
const msgResult   = document.getElementById("msg-result");

const urlInput    = document.getElementById("url-input");
const urlScanBtn  = document.getElementById("url-scan-btn");
const urlPageBtn  = document.getElementById("url-page-btn");
const urlClearBtn = document.getElementById("url-clear-btn");
const urlLoading  = document.getElementById("url-loading");
const urlResult   = document.getElementById("url-result");

const uploadZone  = document.getElementById("upload-zone");
const imgFile     = document.getElementById("img-file");
const imgPreview  = document.getElementById("img-preview");
const imgScanBtn  = document.getElementById("img-scan-btn");
const imgLoading  = document.getElementById("img-loading");
const imgResult   = document.getElementById("img-result");

const historyList = document.getElementById("history-list");
const clearHistBtn = document.getElementById("clear-history-btn");

// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "history") renderHistory();
  });
});

// ── Backend health check ──────────────────────────────────────────────────────
async function checkBackend() {
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2500) });
    const ok = r.ok;
    statusDot.classList.toggle("online", ok);
    statusDot.title = ok ? "Backend online ✓" : "Backend offline";
    backendWarn.style.display = ok ? "none" : "block";
    return ok;
  } catch {
    statusDot.classList.remove("online");
    statusDot.title = "Backend offline";
    backendWarn.style.display = "block";
    return false;
  }
}
checkBackend();
setInterval(checkBackend, 8000);

// ── Pick up pending scan from service worker (context menu) ───────────────────
async function checkPendingScan() {
  const { pending_scan } = await chrome.storage.session.get("pending_scan");
  if (!pending_scan) return;
  await chrome.storage.session.remove("pending_scan");

  if (pending_scan.type === "message" && pending_scan.text) {
    switchTab("message");
    msgInput.value = pending_scan.text;
    scanMessage();
  } else if (pending_scan.type === "url" && pending_scan.url) {
    switchTab("url");
    urlInput.value = pending_scan.url;
    scanURL();
  }
}
checkPendingScan();

function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === "panel-" + name));
}

// ══════════════════════════════════════════════════════════════════════════════
// MESSAGE SCANNING
// ══════════════════════════════════════════════════════════════════════════════

msgScanBtn.addEventListener("click", scanMessage);
msgClearBtn.addEventListener("click", () => { msgInput.value = ""; msgResult.style.display = "none"; });

async function scanMessage() {
  const text = msgInput.value.trim();
  if (!text) { showToast("⚠️ Paste a message first"); return; }
  if (!await checkBackend()) { showToast("❌ Backend is offline"); return; }

  setLoading(msgLoading, msgScanBtn, true);
  msgResult.style.display = "none";

  try {
    const res = await fetch(`${API}/analyze/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    renderMessageResult(data);
    saveHistory({ type: "message", text: text.slice(0, 80), data, ts: Date.now() });
  } catch (e) {
    showToast("❌ " + (e.message || "Request failed"));
  } finally {
    setLoading(msgLoading, msgScanBtn, false);
  }
}

function renderMessageResult(data) {
  const score = data.risk_score ?? data.score ?? 0;
  const level = data.risk_level || (score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");
  const scamType = data.scam_type || data.category || "Unknown";
  const summary  = data.summary  || data.message || data.recommendation || "";
  const reasons  = data.reasons  || data.indicators || [];
  const actions  = data.recommended_actions || [];

  let reasonsHTML = reasons.length
    ? reasons.map(r => `<div class="reason-item">${esc(typeof r === "string" ? r : r.indicator || JSON.stringify(r))}</div>`).join("")
    : "<p>No specific patterns flagged.</p>";

  let actionsHTML = actions.length
    ? actions.map(a => `<div class="reason-item">${esc(a)}</div>`).join("")
    : "";

  const fallbackSummary = summary ||
    (level === "HIGH"   ? "⚠️ This message shows strong indicators of fraud. Do not click any links or share personal information." :
     level === "MEDIUM" ? "⚠️ This message has some suspicious characteristics. Verify the sender before taking any action." :
                          "✅ No obvious scam patterns detected. Stay cautious with unknown senders.");

  msgResult.innerHTML = `
    <div class="score-row">
      <div class="score-circle" style="color:${riskColor(level)}">${score}<span style="font-size:13px;font-weight:400;opacity:0.55">/100</span></div>
      <div>
        <div class="risk-badge risk-${level}">${level} RISK</div>
        <div class="scam-type" style="margin-top:4px;">${esc(scamType)}</div>
      </div>
    </div>
    <div class="result-section"><h4>🧠 AI Assessment</h4><p>${esc(fallbackSummary)}</p></div>
    <div class="result-section"><h4>⚠️ Risk Signals</h4>${reasonsHTML}</div>
    ${actionsHTML ? `<div class="result-section"><h4>✅ Recommended Actions</h4>${actionsHTML}</div>` : ""}
  `;
  msgResult.style.display = "block";
}

// ══════════════════════════════════════════════════════════════════════════════
// URL SCANNING
// ══════════════════════════════════════════════════════════════════════════════

urlScanBtn.addEventListener("click", scanURL);
urlClearBtn.addEventListener("click", () => { urlInput.value = ""; urlResult.style.display = "none"; });
urlPageBtn.addEventListener("click", async () => {
  const res = await chrome.runtime.sendMessage({ action: "get_current_url" });
  if (res?.url) { urlInput.value = res.url; scanURL(); }
  else showToast("⚠️ Could not get page URL");
});

async function scanURL() {
  const url = urlInput.value.trim();
  if (!url) { showToast("⚠️ Enter a URL first"); return; }
  if (!await checkBackend()) { showToast("❌ Backend is offline"); return; }

  setLoading(urlLoading, urlScanBtn, true);
  urlResult.style.display = "none";

  try {
    const res = await fetch(`${API}/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    renderURLResult(data, url);
    saveHistory({ type: "url", text: url.slice(0, 80), data, ts: Date.now() });
  } catch (e) {
    showToast("❌ " + (e.message || "Request failed"));
  } finally {
    setLoading(urlLoading, urlScanBtn, false);
  }
}

// Full security vector matrix — same as main app logic
const ALL_URL_CHECKS = [
  { key: "https",                    label: "SSL / HTTPS",               inv: true  },
  { key: "has_ip",                   label: "IP Address Hostname",        inv: false },
  { key: "has_suspicious_keywords",  label: "Phishing Keywords",          inv: false },
  { key: "has_suspicious_tld",       label: "High-Risk TLD",              inv: false },
  { key: "is_long_url",              label: "Excessive URL Length",       inv: false },
  { key: "has_at_symbol",            label: "@ Symbol in URL",            inv: false },
  { key: "has_multiple_subdomains",  label: "Subdomain Stacking",         inv: false },
  { key: "is_url_shortener",         label: "URL Shortener",              inv: false },
  { key: "has_non_standard_port",    label: "Non-Standard Port",          inv: false },
  { key: "has_encoded_characters",   label: "Encoded Characters",         inv: false },
  { key: "has_multiple_hyphens",     label: "Multiple Hyphens",           inv: false },
  { key: "possible_brand_impersonation", label: "Brand Impersonation",    inv: false },
];

const IND_MAP = {
  "No HTTPS":                    "https",
  "IP address used as hostname": "has_ip",
  "Suspicious keywords":         "has_suspicious_keywords",
  "Suspicious top-level domain": "has_suspicious_tld",
  "Long URL":                    "is_long_url",
  "@ symbol in URL":             "has_at_symbol",
  "Multiple subdomains":         "has_multiple_subdomains",
  "URL shortener":               "is_url_shortener",
  "Non-standard port":           "has_non_standard_port",
  "Encoded characters":          "has_encoded_characters",
  "Multiple hyphens":            "has_multiple_hyphens",
  "Possible brand impersonation":"possible_brand_impersonation",
};

function renderURLResult(data, inputUrl) {
  const score = data.risk_score ?? data.score ?? 0;
  const level = data.risk_level || (score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");
  const rec   = data.recommendation || "";

  // Build flat fields from indicators[] if needed
  let flat = Object.assign({}, data);
  const hasFlat = ALL_URL_CHECKS.some(c => data[c.key] !== undefined);
  if (!hasFlat) {
    ALL_URL_CHECKS.forEach(c => { flat[c.key] = false; });
    flat.https = true;
    const u = (data.url || inputUrl || "").toLowerCase();
    if (u && !u.startsWith("https://")) flat.https = false;
    (data.indicators || []).forEach(ind => {
      const key = IND_MAP[(ind.indicator || "").trim()];
      if (key === "https") flat.https = false;
      else if (key) flat[key] = true;
    });
  }

  const checksHTML = ALL_URL_CHECKS.map(({ key, label, inv }) => {
    const val   = flat[key];
    const isBad = inv ? (val === false) : (val === true);
    return `<div class="check-row">
      <span>${esc(label)}</span>
      <span class="${isBad ? "check-warn" : "check-ok"}">${isBad ? "⚠️ Flag" : "✓ OK"}</span>
    </div>`;
  }).join("");

  // Threat indicators panel
  const inds = data.indicators || [];
  const indsHTML = inds.length
    ? `<div class="result-section"><h4>🚨 Threat Indicators</h4>${inds.map(i => {
        const kw = i.keywords ? ` (${i.keywords.slice(0,3).join(", ")})` : "";
        const tld = i.tld ? ` [${i.tld}]` : "";
        return `<div class="reason-item">${esc((i.indicator||"") + kw + tld)} <span style="float:right;color:#fbbf24;">+${i.score||0}</span></div>`;
      }).join("")}</div>`
    : `<div class="result-section"><h4 style="color:#4ade80;">✅ No Threats Found</h4><p>All checks passed for this URL.</p></div>`;

  // Always show assessment — fallback by risk level
  const assessment = rec ||
    (level === "HIGH"   ? "⚠️ This URL shows high-risk indicators. Avoid entering personal or payment information." :
     level === "MEDIUM" ? "⚠️ This URL has some suspicious characteristics. Proceed with caution." :
                          "✅ No suspicious patterns detected. Exercise standard caution when sharing personal data.");

  // Extract domain from inputUrl if backend didn't return one
  const domain = data.domain || (() => {
    try { return new URL(inputUrl).hostname; } catch { return ""; }
  })();

  const displayUrl = data.url || inputUrl || "";

  urlResult.innerHTML = `
    <div style="margin-bottom:12px;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Analyzed URL</div>
      <div style="font-size:11px;color:#00d4ff;word-break:break-all;font-family:monospace;background:rgba(0,212,255,0.05);padding:6px 10px;border-radius:8px;border:1px solid rgba(0,212,255,0.1);">${esc(displayUrl)}</div>
    </div>
    <div class="score-row">
      <div>
        <div class="score-circle" style="color:${riskColor(level)}">${score}<span style="font-size:13px;font-weight:400;opacity:0.55">/100</span></div>
      </div>
      <div>
        <div class="risk-badge risk-${level}">${level} RISK</div>
        ${domain ? `<div style="font-size:11px;color:#94a3b8;margin-top:4px;">🌐 ${esc(domain)}</div>` : ""}
      </div>
    </div>
    <div class="result-section"><h4>🔎 Security Matrix</h4>${checksHTML}</div>
    ${indsHTML}
    <div class="result-section">
      <h4>🛡️ Forensic Assessment</h4>
      <p>${esc(assessment)}</p>
    </div>
  `;
  urlResult.style.display = "block";
}

// ══════════════════════════════════════════════════════════════════════════════
// IMAGE / SCREENSHOT SCANNING
// ══════════════════════════════════════════════════════════════════════════════

uploadZone.addEventListener("click", () => imgFile.click());
imgFile.addEventListener("change", handleFileSelect);
uploadZone.addEventListener("dragover", e => { e.preventDefault(); uploadZone.classList.add("drag"); });
uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("drag"));
uploadZone.addEventListener("drop", e => {
  e.preventDefault(); uploadZone.classList.remove("drag");
  const f = e.dataTransfer.files[0];
  if (f && f.type.startsWith("image/")) setImageFile(f);
});

function handleFileSelect(e) {
  const f = e.target.files[0];
  if (f) setImageFile(f);
}

function setImageFile(f) {
  selectedFile = f;
  imgScanBtn.disabled = false;
  const reader = new FileReader();
  reader.onload = ev => { imgPreview.src = ev.target.result; imgPreview.style.display = "block"; };
  reader.readAsDataURL(f);
}

imgScanBtn.addEventListener("click", scanImage);

async function scanImage() {
  if (!selectedFile) { showToast("⚠️ Select an image first"); return; }
  if (!await checkBackend()) { showToast("❌ Backend is offline"); return; }

  setLoading(imgLoading, imgScanBtn, true);
  imgResult.style.display = "none";

  try {
    const formData = new FormData();
    formData.append("file", selectedFile);

    const res = await fetch(`${API}/analyze/image`, { method: "POST", body: formData });
    const data = await res.json();
    renderMessageResult_toEl(data, imgResult);
    saveHistory({ type: "image", text: "Screenshot scan", data, ts: Date.now() });
  } catch (e) {
    showToast("❌ " + (e.message || "Request failed"));
  } finally {
    setLoading(imgLoading, imgScanBtn, false);
  }
}

function renderMessageResult_toEl(data, el) {
  const score = data.risk_score ?? data.score ?? 0;
  const level = data.risk_level || (score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");
  const scamType = data.scam_type || data.category || "Unknown";
  const summary  = data.summary  || data.recommendation || "";
  const reasons  = data.reasons  || [];
  const extracted = data.extracted_text || data.text || "";

  let reasonsHTML = reasons.length
    ? reasons.map(r => `<div class="reason-item">${esc(r)}</div>`).join("")
    : "<p>No specific patterns flagged.</p>";

  el.innerHTML = `
    <div class="score-row">
      <div class="score-circle" style="color:${riskColor(level)}">${score}</div>
      <div>
        <div class="risk-badge risk-${level}">${level} RISK</div>
        <div class="scam-type" style="margin-top:4px;">${esc(scamType)}</div>
      </div>
    </div>
    ${extracted ? `<div class="result-section"><h4>📝 Extracted Text</h4><p style="font-family:monospace;font-size:11px;">${esc(extracted.slice(0,200))}${extracted.length>200?"…":""}</p></div>` : ""}
    ${summary ? `<div class="result-section"><h4>🧠 Assessment</h4><p>${esc(summary)}</p></div>` : ""}
    <div class="result-section"><h4>⚠️ Risk Signals</h4>${reasonsHTML}</div>
  `;
  el.style.display = "block";
}

// ══════════════════════════════════════════════════════════════════════════════
// HISTORY
// ══════════════════════════════════════════════════════════════════════════════

async function saveHistory(item) {
  const { history = [] } = await chrome.storage.local.get("history");
  history.unshift(item);
  if (history.length > 50) history.length = 50;
  await chrome.storage.local.set({ history });
}

async function renderHistory() {
  const { history = [] } = await chrome.storage.local.get("history");
  if (!history.length) {
    historyList.innerHTML = `<div class="history-empty">No scans yet.<br>Start by scanning a message or URL.</div>`;
    return;
  }
  historyList.innerHTML = history.map((h, i) => {
    const score = h.data?.risk_score ?? h.data?.score ?? 0;
    const level = h.data?.risk_level || (score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");
    const icon  = { message: "💬", url: "🔗", image: "🖼️" }[h.type] || "🔍";
    const time  = new Date(h.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return `<div class="history-item" data-idx="${i}">
      <div class="h-top">
        <span class="h-type">${icon} ${h.type}</span>
        <span class="h-score" style="color:${riskColor(level)}">${score}/100 <span class="risk-badge risk-${level}" style="font-size:10px;">${level}</span></span>
      </div>
      <div class="h-text">${esc(h.text)}</div>
      <div style="font-size:10px;color:#475569;margin-top:3px;">${time}</div>
    </div>`;
  }).join("");
}

clearHistBtn.addEventListener("click", async () => {
  await chrome.storage.local.remove("history");
  renderHistory();
  showToast("🗑️ History cleared");
});

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function riskColor(level) {
  return level === "HIGH" ? "#f87171" : level === "MEDIUM" ? "#fbbf24" : "#4ade80";
}

function esc(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function setLoading(loadEl, btn, on) {
  loadEl.style.display = on ? "block" : "none";
  btn.disabled = on;
}

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2500);
}

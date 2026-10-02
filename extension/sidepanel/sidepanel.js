// ── ScamShield AI — Side Panel JS ────────────────────────────────────────────
// Mirrors the website's exact result layout: SVG gauge, risk breakdown cards,
// reasons list (⚠️), actions list (🛡️), and action buttons.

const API = "http://127.0.0.1:8000";
let selectedFile = null;

// ── DOM refs ─────────────────────────────────────────────────────────────────
const statusDot     = document.getElementById("status-dot");
const msgInput      = document.getElementById("msg-input");
const msgScanBtn    = document.getElementById("msg-scan-btn");
const msgClearBtn   = document.getElementById("msg-clear-btn");
const msgLoading    = document.getElementById("msg-loading");
const msgResult     = document.getElementById("msg-result");
const backendWarn   = document.getElementById("backend-warn-msg");

const urlInput      = document.getElementById("url-input");
const urlScanBtn    = document.getElementById("url-scan-btn");
const urlPageBtn    = document.getElementById("url-page-btn");
const urlClearBtn   = document.getElementById("url-clear-btn");
const urlLoading    = document.getElementById("url-loading");
const urlResult     = document.getElementById("url-result");

const uploadZone    = document.getElementById("upload-zone");
const imgFile       = document.getElementById("img-file");
const imgPreview    = document.getElementById("img-preview");
const imgScanBtn    = document.getElementById("img-scan-btn");
const imgLoading    = document.getElementById("img-loading");
const imgResult     = document.getElementById("img-result");

const historyList   = document.getElementById("history-list");
const clearHistBtn  = document.getElementById("clear-history-btn");

// ── Tabs ──────────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "history") renderHistory();
  });
});

function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === "panel-" + name));
}

// ── Backend health ────────────────────────────────────────────────────────────
async function checkBackend() {
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2500) });
    const ok = r.ok;
    statusDot.classList.toggle("online", ok);
    statusDot.title = ok ? "Backend online ✓" : "Backend offline";
    if (backendWarn) backendWarn.style.display = ok ? "none" : "block";
    return ok;
  } catch {
    statusDot.classList.remove("online");
    statusDot.title = "Backend offline";
    if (backendWarn) backendWarn.style.display = "block";
    return false;
  }
}
checkBackend();
setInterval(checkBackend, 8000);

// ── Context-menu pending scan ─────────────────────────────────────────────────
async function checkPendingScan() {
  const { pending_scan } = await chrome.storage.session.get("pending_scan");
  if (!pending_scan) return;
  await chrome.storage.session.remove("pending_scan");
  if (pending_scan.type === "message" && pending_scan.text) {
    switchTab("message"); msgInput.value = pending_scan.text; scanMessage();
  } else if (pending_scan.type === "url" && pending_scan.url) {
    switchTab("url"); urlInput.value = pending_scan.url; scanURL();
  }
}
checkPendingScan();

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS — exact match with website functions
// ══════════════════════════════════════════════════════════════════════════════

function esc(str) {
  return String(str ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function getRiskColor(level) {
  if (!level) return "#00f5c8";
  const l = level.toUpperCase();
  if (l === "HIGH")   return "#ff3366";
  if (l === "MEDIUM") return "#ffb703";
  return "#00f5c8";
}

function getRiskClass(level) {
  if (!level) return "risk-low";
  const l = level.toUpperCase();
  if (l === "HIGH")   return "risk-high";
  if (l === "MEDIUM") return "risk-medium";
  return "risk-low";
}

function getSignalIcon(level) {
  if (!level) return "⚠️";
  const l = level.toUpperCase();
  if (l === "HIGH")   return "🚨";
  if (l === "MEDIUM") return "⚠️";
  return "ℹ️";
}

function getSeverityClass(level) {
  if (!level) return "severity-medium";
  const l = level.toUpperCase();
  if (l === "HIGH")   return "severity-high";
  if (l === "MEDIUM") return "severity-medium";
  return "severity-low";
}

function updateGauge(el, score, level) {
  const circle = el.querySelector(".gauge-progress");
  if (!circle) return;
  const circumference = 283;
  const pct = Math.min(Math.max(score, 0), 100) / 100;
  const offset = circumference - pct * circumference;
  circle.style.strokeDashoffset = offset;
  const color = getRiskColor(level);
  circle.style.stroke = color;
  const numEl = el.querySelector(".gauge-score-num");
  if (numEl) numEl.style.color = color;
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

async function saveHistory(item) {
  const { history = [] } = await chrome.storage.local.get("history");
  history.unshift(item);
  if (history.length > 50) history.length = 50;
  await chrome.storage.local.set({ history });
}

// ══════════════════════════════════════════════════════════════════════════════
// MESSAGE SCANNER
// ══════════════════════════════════════════════════════════════════════════════

msgScanBtn.addEventListener("click", scanMessage);
msgClearBtn.addEventListener("click", () => {
  msgInput.value = "";
  msgResult.style.display = "none";
  msgResult.innerHTML = "";
});

async function scanMessage() {
  const text = msgInput.value.trim();
  if (!text) { showToast("⚠️ Paste a message first"); return; }
  if (!await checkBackend()) { showToast("❌ Backend is offline"); return; }

  setLoading(msgLoading, msgScanBtn, true);
  msgResult.style.display = "none";

  try {
    const res = await fetch(`${API}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text })
    });
    const resp = await res.json();
    const data = resp.final_analysis || resp;
    renderMessageResult(data, msgResult);
    saveHistory({ type: "message", text: text.slice(0, 80), data, ts: Date.now() });
  } catch (e) {
    showToast("❌ " + (e.message || "Request failed"));
  } finally {
    setLoading(msgLoading, msgScanBtn, false);
  }
}

// ── Render message result — EXACT same layout as website ──────────────────────
function renderMessageResult(data, el) {
  const score      = Number(data.risk_score || data.score || 0);
  const level      = data.risk_level || (score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");
  const confidence = Number(data.confidence || 85);
  const scamType   = data.scam_type || data.category || "Unknown Threat";
  const summary    = data.summary || "ScamShield analyzed the message using multi-layered threat heuristics.";
  const reasons    = Array.isArray(data.reasons) ? data.reasons : [];
  const actions    = Array.isArray(data.recommended_actions) ? data.recommended_actions : [];
  const breakdown  = Array.isArray(data.risk_breakdown) ? data.risk_breakdown : [];
  const mode       = data.score_mode || "HYBRID_ENGINE";
  const riskClass  = getRiskClass(level);

  // Reasons list
  const reasonsHTML = reasons.length > 0
    ? reasons.map(r => `<li>${esc(r)}</li>`).join("")
    : `<li>No major warning signals were detected.</li>`;

  // Actions list
  const actionsHTML = actions.length > 0
    ? actions.map(a => `<li>${esc(a)}</li>`).join("")
    : `<li>Stay cautious and verify the source before taking any action.</li>`;

  // Risk breakdown signals — same as website's displaySmartExplanation
  let breakdownHTML = "";
  if (breakdown.length > 0) {
    breakdownHTML = breakdown.map(signal => {
      const sev       = String(signal.severity || "MEDIUM").toLowerCase();
      const icon      = getSignalIcon(signal.severity);
      const sevClass  = getSeverityClass(signal.severity);
      const sc        = Number(signal.score || 0);
      const name      = signal.signal || "Suspicious Threat Signal";
      const expl      = signal.explanation || "A suspicious indicator was recognised.";
      return `
        <div class="risk-signal ${sev}">
          <div class="risk-signal-header">
            <div class="signal-name"><span>${icon}</span><span>${esc(name)}</span></div>
            <span class="signal-score ${sevClass}">+${sc} • ${esc(String(signal.severity || "MEDIUM").toUpperCase())}</span>
          </div>
          <div class="signal-explanation">${esc(expl)}</div>
        </div>`;
    }).join("");
  } else if (score === 0 || level === "LOW") {
    breakdownHTML = `
      <div class="risk-signal low">
        <div class="risk-signal-header">
          <div class="signal-name"><span>ℹ️</span><span>No Major Warning Signals</span></div>
          <span class="signal-score severity-low">LOW RISK</span>
        </div>
        <div class="signal-explanation">ScamShield did not detect high-probability fraudulent patterns in this content.</div>
      </div>`;
  }

  el.innerHTML = `
    <div class="result-top">
      <div class="gauge-wrapper">
        <div class="gauge-svg-box">
          <svg class="gauge-svg" viewBox="0 0 100 100">
            <circle class="gauge-bg" cx="50" cy="50" r="45"></circle>
            <circle class="gauge-progress" cx="50" cy="50" r="45"></circle>
          </svg>
          <div class="gauge-center-text">
            <span class="gauge-score-num" style="color:${getRiskColor(level)}">${score}</span>
            <span class="gauge-score-sub">/ 100</span>
          </div>
        </div>
        <div class="risk-level-badge-wrap">
          <div class="risk-label ${riskClass}">
            <span>${getSignalIcon(level)}</span>
            <span>${esc(level)} RISK</span>
          </div>
          <span class="confidence-text">Confidence: <b>${confidence}%</b></span>
        </div>
      </div>
      <div class="result-heading-box">
        <h3>${esc(scamType)}</h3>
        <p>${esc(summary)}</p>
      </div>
    </div>

    <div class="result-info">
      <div class="info-box">
        <div class="info-label">Risk Score</div>
        <div class="info-value" style="color:${getRiskColor(level)}">${score} / 100</div>
      </div>
      <div class="info-box">
        <div class="info-label">Confidence</div>
        <div class="info-value">${confidence}%</div>
      </div>
      <div class="info-box">
        <div class="info-label">Mode</div>
        <div class="info-value" style="font-size:10px">${esc(mode)}</div>
      </div>
    </div>

    ${breakdownHTML ? `
    <div class="result-section">
      <h4>🧠 AI Risk Breakdown</h4>
      <div class="risk-breakdown">${breakdownHTML}</div>
    </div>` : ""}

    <div class="result-section">
      <h4>⚠️ Flagged Risk Indicators</h4>
      <ul class="reasons-list">${reasonsHTML}</ul>
    </div>

    <div class="result-section">
      <h4>🛡️ Recommended Safeguards</h4>
      <ul class="actions-list">${actionsHTML}</ul>
    </div>

    <div class="report-action-bar">
      <button class="action-pill-btn" onclick="copyReport('${esc(scamType)}',${score},'${esc(level)}')">📋 Copy Incident Report</button>
      <button class="action-pill-btn" onclick="window.open('https://cybercrime.gov.in','_blank')">🚨 Report to Cyber Crime ↗</button>
    </div>
  `;
  el.style.display = "block";
  setTimeout(() => updateGauge(el, score, level), 60);
}

// Copy threat report to clipboard
window.copyReport = function(type, score, level) {
  const report =
`[SCAMSHIELD AI THREAT REPORT]
Date: ${new Date().toLocaleString()}
Scam Classification: ${type}
Assessed Risk Score: ${score}/100 (${level} RISK)
Source Analyzed: Message Inspection Engine
Status: Verified by ScamShield Defense System
Guidance: Do not share credentials or click unverified links.`;
  navigator.clipboard.writeText(report)
    .then(() => showToast("📋 Threat Report copied!"))
    .catch(() => showToast("⚠️ Could not copy to clipboard"));
};

// ══════════════════════════════════════════════════════════════════════════════
// URL SCANNER
// ══════════════════════════════════════════════════════════════════════════════

urlScanBtn.addEventListener("click", scanURL);
urlClearBtn.addEventListener("click", () => { urlInput.value = ""; urlResult.style.display = "none"; urlResult.innerHTML = ""; });
urlPageBtn.addEventListener("click", async () => {
  const res = await chrome.runtime.sendMessage({ action: "get_current_url" });
  if (res?.url) { urlInput.value = res.url; scanURL(); }
  else showToast("⚠️ Could not get page URL");
});

const ALL_URL_CHECKS = [
  { key:"https",                    label:"SSL / HTTPS",           inv:true  },
  { key:"has_ip",                   label:"IP Address Hostname",   inv:false },
  { key:"has_suspicious_keywords",  label:"Phishing Keywords",     inv:false },
  { key:"has_suspicious_tld",       label:"High-Risk TLD",         inv:false },
  { key:"is_long_url",              label:"Excessive URL Length",  inv:false },
  { key:"has_at_symbol",            label:"@ Symbol in URL",       inv:false },
  { key:"has_multiple_subdomains",  label:"Subdomain Stacking",    inv:false },
  { key:"is_url_shortener",         label:"URL Shortener",         inv:false },
  { key:"has_non_standard_port",    label:"Non-Standard Port",     inv:false },
  { key:"has_encoded_characters",   label:"Encoded Characters",    inv:false },
  { key:"has_multiple_hyphens",     label:"Multiple Hyphens",      inv:false },
  { key:"possible_brand_impersonation", label:"Brand Impersonation",inv:false},
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

async function scanURL() {
  const url = urlInput.value.trim();
  if (!url) { showToast("⚠️ Enter a URL first"); return; }
  if (!await checkBackend()) { showToast("❌ Backend is offline"); return; }

  setLoading(urlLoading, urlScanBtn, true);
  urlResult.style.display = "none";

  try {
    const res = await fetch(`${API}/api/analyze-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const resp = await res.json();
    const data = resp.url_analysis || resp;
    renderURLResult(data, url);
    saveHistory({ type: "url", text: url.slice(0, 80), data, ts: Date.now() });
  } catch (e) {
    showToast("❌ " + (e.message || "Request failed"));
  } finally {
    setLoading(urlLoading, urlScanBtn, false);
  }
}

function renderURLResult(data, inputUrl) {
  const score = Number(data.risk_score ?? data.score ?? 0);
  const level = data.risk_level || (score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");
  const riskClass = getRiskClass(level);

  // Resolve flat booleans from indicators[] if needed
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

  // Security matrix
  const checksHTML = ALL_URL_CHECKS.map(({ key, label, inv }) => {
    const val   = flat[key];
    const isBad = inv ? (val === false) : (val === true);
    return `<div class="check-row">
      <span>${esc(label)}</span>
      <span class="${isBad ? "check-warn" : "check-ok"}">${isBad ? "⚠️ FLAGGED" : "✓ CLEAN"}</span>
    </div>`;
  }).join("");

  // Threat indicator breakdown (styled like risk-signal cards)
  const inds = data.indicators || [];
  let indHTML = "";
  if (inds.length > 0) {
    indHTML = `<div class="result-section"><h4>🚨 Threat Indicators Detected</h4><div class="risk-breakdown">` +
      inds.map(i => {
        const kw  = i.keywords ? ` — Keywords: ${i.keywords.slice(0,4).join(", ")}` : "";
        const tld = i.tld      ? ` — TLD: ${i.tld}` : "";
        const brd = i.brands   ? ` — Brands: ${i.brands.slice(0,3).join(", ")}` : "";
        const sc  = i.score || 0;
        return `<div class="risk-signal high">
          <div class="risk-signal-header">
            <div class="signal-name"><span>🚨</span><span>${esc(i.indicator || "Unknown")}</span></div>
            <span class="signal-score severity-high">+${sc} pts</span>
          </div>
          <div class="signal-explanation">${esc(kw + tld + brd || "Suspicious pattern detected in this URL.")}</div>
        </div>`;
      }).join("") +
    `</div></div>`;
  } else {
    indHTML = `<div class="result-section">
      <h4 style="color:var(--risk-low);">✅ No Threat Indicators Found</h4>
      <div class="risk-signal low">
        <div class="risk-signal-header">
          <div class="signal-name"><span>ℹ️</span><span>All Checks Passed</span></div>
          <span class="signal-score severity-low">SAFE</span>
        </div>
        <div class="signal-explanation">No known phishing patterns, suspicious keywords, or high-risk TLDs were detected in this URL.</div>
      </div>
    </div>`;
  }

  // Assessment text
  const rec = data.recommendation ||
    (level === "HIGH"   ? "⚠️ This URL shows multiple high-risk indicators. Do not enter personal or payment information." :
     level === "MEDIUM" ? "⚠️ This URL has some suspicious characteristics. Proceed with caution." :
                          "✅ No suspicious patterns detected. Exercise standard caution when sharing personal data.");

  const domain = data.domain || (() => { try { return new URL(inputUrl).hostname; } catch { return ""; } })();
  const displayUrl = data.url || inputUrl || "";

  urlResult.innerHTML = `
    <div class="result-top">
      <div class="gauge-wrapper">
        <div class="gauge-svg-box">
          <svg class="gauge-svg" viewBox="0 0 100 100">
            <circle class="gauge-bg" cx="50" cy="50" r="45"></circle>
            <circle class="gauge-progress" cx="50" cy="50" r="45"></circle>
          </svg>
          <div class="gauge-center-text">
            <span class="gauge-score-num" style="color:${getRiskColor(level)}">${score}</span>
            <span class="gauge-score-sub">/ 100</span>
          </div>
        </div>
        <div class="risk-level-badge-wrap">
          <div class="risk-label ${riskClass}">
            <span>${getSignalIcon(level)}</span>
            <span>${esc(level)} RISK</span>
          </div>
          ${domain ? `<span class="confidence-text" style="margin-top:6px;">🌐 ${esc(domain)}</span>` : ""}
        </div>
      </div>
      <div class="result-heading-box">
        <h3>URL Forensic Report</h3>
        <p style="word-break:break-all;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--primary-cyan);">${esc(displayUrl)}</p>
      </div>
    </div>

    <div class="result-section">
      <h4>🔎 Security Vector Matrix</h4>
      ${checksHTML}
    </div>

    ${indHTML}

    <div class="result-section">
      <h4>🛡️ Forensic Assessment</h4>
      <ul class="actions-list"><li>${esc(rec)}</li></ul>
    </div>

    <div class="report-action-bar">
      <button class="action-pill-btn" onclick="window.open('https://cybercrime.gov.in','_blank')">🚨 Report to Cyber Crime ↗</button>
    </div>
  `;
  urlResult.style.display = "block";
  setTimeout(() => updateGauge(urlResult, score, level), 60);
}

// ══════════════════════════════════════════════════════════════════════════════
// IMAGE SCANNER
// ══════════════════════════════════════════════════════════════════════════════

uploadZone.addEventListener("click", () => imgFile.click());
imgFile.addEventListener("change", e => { if (e.target.files[0]) setImageFile(e.target.files[0]); });
uploadZone.addEventListener("dragover", e => { e.preventDefault(); uploadZone.classList.add("drag"); });
uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("drag"));
uploadZone.addEventListener("drop", e => {
  e.preventDefault(); uploadZone.classList.remove("drag");
  const f = e.dataTransfer.files[0];
  if (f && f.type.startsWith("image/")) setImageFile(f);
});

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
    const res  = await fetch(`${API}/api/analyze-image`, { method: "POST", body: formData });
    const resp = await res.json();
    const data = resp.final_analysis || resp;
    // Attach extracted text if available
    if (resp.extracted_text) data._extracted_text = resp.extracted_text;
    renderImageResult(data, imgResult);
    saveHistory({ type: "image", text: "Screenshot scan", data, ts: Date.now() });
  } catch (e) {
    showToast("❌ " + (e.message || "Request failed"));
  } finally {
    setLoading(imgLoading, imgScanBtn, false);
  }
}

function renderImageResult(data, el) {
  const extracted = data._extracted_text || data.extracted_text || "";
  // Re-use full message result layout, add extracted text section
  renderMessageResult(data, el);
  if (extracted) {
    const extraSection = document.createElement("div");
    extraSection.className = "result-section";
    extraSection.innerHTML = `
      <h4>📝 Extracted Text (OCR)</h4>
      <div style="background:rgba(255,255,255,0.03);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:12px 14px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#94a3b8;line-height:1.6;word-break:break-word;">
        ${esc(extracted.slice(0, 400))}${extracted.length > 400 ? "…" : ""}
      </div>`;
    // Insert before report-action-bar
    const bar = el.querySelector(".report-action-bar");
    if (bar) el.insertBefore(extraSection, bar);
    else el.appendChild(extraSection);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// HISTORY
// ══════════════════════════════════════════════════════════════════════════════

async function renderHistory() {
  const { history = [] } = await chrome.storage.local.get("history");
  if (!history.length) {
    historyList.innerHTML = `<div class="history-empty">No scans yet.<br>Start by scanning a message or URL.</div>`;
    return;
  }
  historyList.innerHTML = history.map((h, i) => {
    const score = h.data?.risk_score ?? h.data?.score ?? 0;
    const level = h.data?.risk_level || (score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW");
    const icon  = { message:"💬", url:"🔗", image:"🖼️" }[h.type] || "🔍";
    const time  = new Date(h.ts).toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" });
    return `<div class="history-item" data-idx="${i}">
      <div class="h-top">
        <span class="h-type">${icon} ${h.type}</span>
        <span class="risk-label ${getRiskClass(level)}" style="padding:3px 10px;font-size:10px;margin-top:0;">${score}/100 ${level}</span>
      </div>
      <div class="h-text">${esc(h.text)}</div>
      <div class="h-time">${time}</div>
    </div>`;
  }).join("");
}

clearHistBtn.addEventListener("click", async () => {
  await chrome.storage.local.remove("history");
  renderHistory();
  showToast("🗑️ History cleared");
});

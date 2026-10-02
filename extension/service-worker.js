// ── ScamShield AI — Service Worker (Manifest V3) ────────────────────────────
// Opens the side panel on icon click and registers context menu items.

const API_BASE = "http://127.0.0.1:8000";

// ── Open side panel on toolbar icon click ────────────────────────────────────
chrome.action.onClicked.addListener(async (tab) => {
  await chrome.sidePanel.open({ windowId: tab.windowId });
});

// ── Set default side panel behaviour on install ──────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
  // Create context menu items
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "scamshield_scan_text",
      title: "🛡️ Scan with ScamShield AI",
      contexts: ["selection"]
    });

    chrome.contextMenus.create({
      id: "scamshield_scan_url",
      title: "🔗 Inspect this URL with ScamShield AI",
      contexts: ["link", "page"]
    });
  });

  // Store the API base URL so sidepanel can retrieve it
  await chrome.storage.local.set({ api_base: API_BASE });
});

// ── Context menu click handler ────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "scamshield_scan_text") {
    const text = info.selectionText || "";
    await chrome.storage.session.set({
      pending_scan: { type: "message", text }
    });
    await chrome.sidePanel.open({ windowId: tab.windowId });
    showBadgeFlash("✓");
  }

  if (info.menuItemId === "scamshield_scan_url") {
    const url = info.linkUrl || info.pageUrl || "";
    await chrome.storage.session.set({
      pending_scan: { type: "url", url }
    });
    await chrome.sidePanel.open({ windowId: tab.windowId });
    showBadgeFlash("✓");
  }
});

// ── Message from sidepanel / content scripts ──────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "get_current_url") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      sendResponse({ url: tab?.url || "" });
    })();
    return true; // keep channel open
  }

  if (message.action === "scan_current_page_url") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab?.url || "";
      await chrome.storage.session.set({ pending_scan: { type: "url", url } });
      sendResponse({ ok: true });
    })();
    return true;
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
async function showBadgeFlash(text) {
  await chrome.action.setBadgeText({ text });
  await chrome.action.setBadgeBackgroundColor({ color: "#00d4ff" });
  setTimeout(async () => {
    await chrome.action.setBadgeText({ text: "" });
  }, 2000);
}

// ── ScamShield AI — Content Script ────────────────────────────────────────────
// Listens for messages from the service worker.
// Currently used only for right-click text selection relay.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "get_selected_text") {
    sendResponse({ text: window.getSelection()?.toString() || "" });
  }
});

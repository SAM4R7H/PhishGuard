/**
 * ============================================
 * BACKGROUND.JS — Service Worker
 * Role: Integration & Privacy Lead
 * Purpose: Message routing, state management
 * ============================================
 */

// ── 1. Initialize on Install ──
chrome.runtime.onInstalled.addListener((details) => {
  console.log("[PhishGuard] Installed/Updated:", details.reason);

  chrome.storage.local.set({
    stats: {
      totalScans: 0,
      scamsDetected: 0,
      safeEmails: 0,
      categoryCounts: {},
      installDate: Date.now()
    },
    settings: {
      isEnabled: true,
      sensitivity: "medium"
    },
    scanHistory: []
  });
});

// ── 2. Message Router ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // console.log("[PhishGuard BG] Received:", message.type || message.action);

  // Handle different message types
  const msgType = message.type || message.action;

  switch (msgType) {
    
    // Case A: Content script sends a scan result (Update Badge)
    case "SCAN_COMPLETE":
      handleScanComplete(message.payload, sender.tab);
      sendResponse({ received: true });
      break;

    // Case B: Content script asks to save data (The Fix!)
    case "SAVE_RESULT":
      saveResultToStorage(message.payload);
      sendResponse({ status: "saving" });
      break;

    // Case C: Popup asks for stats
    case "GET_STATS":
      chrome.storage.local.get(['stats'], (data) => {
        sendResponse(data.stats || {});
      });
      return true; // Keep channel open for async response

    // Case D: Popup asks for history
    case "GET_HISTORY":
      chrome.storage.local.get(['scanHistory'], (data) => {
        sendResponse(data.scanHistory || []);
      });
      return true;

    // Case E: Clear History
    case "CLEAR_HISTORY":
    case "RESET_STATS":
      chrome.storage.local.set({ 
        scanHistory: [],
        stats: { totalScans: 0, scamsDetected: 0, safeEmails: 0, categoryCounts: {} }
      });
      sendResponse({ success: true });
      break;

    default:
      // console.log("Unknown message:", msgType);
      break;
  }
});

// ── Helper: Save to Storage (Runs in Background) ──
async function saveResultToStorage(result) {
  try {
    const data = await chrome.storage.local.get(['scanHistory', 'stats']);
    
    const history = data.scanHistory || [];
    const stats = data.stats || {
      totalScans: 0, scamsDetected: 0, safeEmails: 0, categoryCounts: {}
    };

    // Self-Healing
    if (!stats.categoryCounts) stats.categoryCounts = {};

    // Add to history
    history.unshift({ ...result, timestamp: Date.now() });
    if (history.length > 100) history.pop();

    // Update stats
    stats.totalScans++;
    if (result.score >= 70) stats.scamsDetected++;
    else stats.safeEmails++;
    
    if (result.category) {
      stats.categoryCounts[result.category] = (stats.categoryCounts[result.category] || 0) + 1;
    }

    await chrome.storage.local.set({ scanHistory: history, stats });
    console.log("[PhishGuard BG] Data saved.");
  } catch (e) {
    console.error("[PhishGuard BG] Save Error:", e);
  }
}

// ── Helper: Update Icon Badge ──
function handleScanComplete(result, tab) {
  if (!tab || !tab.id) return;

  if (result.score >= 70) {
    chrome.action.setBadgeText({ text: "!", tabId: tab.id });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: tab.id });
  } else if (result.score >= 30) {
    chrome.action.setBadgeText({ text: "⚡", tabId: tab.id });
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId: tab.id });
  } else {
    chrome.action.setBadgeText({ text: "✓", tabId: tab.id });
    chrome.action.setBadgeBackgroundColor({ color: "#22c55e", tabId: tab.id });
  }
}
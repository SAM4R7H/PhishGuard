// background.js - The Command Center for PhishGuard

// 1. Initialize Extension on Install
chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard: Successfully Installed!");
  
  // Set default settings in local storage
  chrome.storage.local.set({
    stats: {
      scamsBlocked: 0,
      emailsScanned: 0
    },
    settings: {
      privacyMode: true,
      sensitivity: "medium"
    }
  });
});

// 2. Listen for messages from Content Scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateStats") {
    // Logic to increment scam count
    chrome.storage.local.get(['stats'], (result) => {
      let newStats = result.stats;
      newStats.scamsBlocked += 1;
      chrome.storage.local.set({ stats: newStats });
    });
  }
});
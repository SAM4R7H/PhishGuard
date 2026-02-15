/**
 * ============================================
 * POPUP.JS — Extension Popup Logic
 * Purpose: Display stats, handle user actions,
 * communicate with background script
 * ============================================
 */

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadLastScan();
  setupEventListeners();
});


// ── Load and Display Stats ──
async function loadStats() {
  try {
    const stats = await sendMessage({ type: "GET_STATS" });
    if (!stats) return;

    document.getElementById('totalScans').textContent = stats.totalScans || 0;
    document.getElementById('scamsDetected').textContent = stats.scamsDetected || 0;
    document.getElementById('safeEmails').textContent = stats.safeEmails || 0;

    // Calculate detection rate
    if (stats.totalScans > 0) {
      const rate = Math.round((stats.scamsDetected / stats.totalScans) * 100);
      document.getElementById('accuracy').textContent = `${rate}%`;
    }

    // Show categories if available
    if (stats.categoryCounts && Object.keys(stats.categoryCounts).length > 0) {
      showCategories(stats.categoryCounts);
    }
  } catch (error) {
    console.error("Error loading stats:", error);
  }
}


// ── Load Last Scan Result ──
async function loadLastScan() {
  try {
    const history = await sendMessage({ type: "GET_HISTORY" });
    if (!history || history.length === 0) return;

    const lastScan = history[0];
    const section = document.getElementById('lastScanSection');
    const resultDiv = document.getElementById('lastScanResult');

    let scoreColor;
    if (lastScan.score >= 70) scoreColor = '#ef4444';
    else if (lastScan.score >= 30) scoreColor = '#f59e0b';
    else scoreColor = '#22c55e';

    resultDiv.innerHTML = `
      <div class="result-score" style="color: ${scoreColor}">
        ${lastScan.categoryIcon || '📧'} ${lastScan.riskLevel} — Score: ${lastScan.score}/100
      </div>
      <div class="result-category">${lastScan.category || 'General'}</div>
      <div class="result-flags">
        ${(lastScan.explanation?.details || []).slice(0, 3)
          .map(f => `<div>• ${f}</div>`).join('')}
      </div>
      <div style="font-size:11px;color:#64748b;margin-top:6px;">
        ${timeAgo(lastScan.timestamp)}
      </div>
    `;

    section.style.display = 'block';
  } catch (error) {
    console.error("Error loading last scan:", error);
  }
}


// ── Show Category Breakdown ──
function showCategories(categoryCounts) {
  const section = document.getElementById('categoriesSection');
  const list = document.getElementById('categoryList');

  const sorted = Object.entries(categoryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  list.innerHTML = sorted
    .map(([category, count]) => `
      <div class="category-item">
        <span>${category}</span>
        <span class="category-count">${count}</span>
      </div>
    `).join('');

  section.style.display = 'block';
}


// ── Event Listeners ──
function setupEventListeners() {
  // Manual scan button
  document.getElementById('manualScanBtn').addEventListener('click', async () => {
    const btn = document.getElementById('manualScanBtn');
    btn.textContent = '⏳ Scanning...';
    btn.disabled = true;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (tab && tab.url.includes('mail.google.com')) {
        await chrome.tabs.sendMessage(tab.id, { type: "MANUAL_SCAN" });
        btn.textContent = '✅ Scan Triggered!';
      } else {
        btn.textContent = '⚠️ Open Gmail First';
      }
    } catch (error) {
      btn.textContent = '❌ Error — Open Gmail';
    }

    setTimeout(() => {
      btn.textContent = '🔍 Scan Current Email';
      btn.disabled = false;
    }, 2000);
  });

  // Clear history button
  document.getElementById('clearHistoryBtn').addEventListener('click', async () => {
    await sendMessage({ type: "CLEAR_HISTORY" });
    await sendMessage({ type: "RESET_STATS" });
    loadStats();
    document.getElementById('lastScanSection').style.display = 'none';
    document.getElementById('categoriesSection').style.display = 'none';
  });
}


// ── Helper: Send message to background ──
function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      resolve(response);
    });
  });
}


// ── Helper: Time ago ──
function timeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
  return `${Math.floor(seconds / 86400)} days ago`;
}
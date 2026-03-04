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

    // determine color for score and gauge
    let gaugeClass = 'safe';
    if (lastScan.score >= 70) gaugeClass = 'danger';
    else if (lastScan.score >= 30) gaugeClass = 'warning';
    const scoreColor = (gaugeClass==='danger' ? '#ef4444' : gaugeClass==='warning' ? '#f59e0b' : '#22c55e');

    const detailsHtml = (lastScan.explanation?.details || []).map(d => {
      const code = d.code || null;
      const msg = d.message || d;
      const explanation = getFlagExplanation(code);
      return `
      <div class="flag-item">
        <span class="flag-icon">⚠️</span>
        <span class="flag-message">${msg}</span>
        ${explanation ? `<div class="flag-explanation">${explanation}</div>` : ''}
      </div>
    `;
    }).join('');

    resultDiv.innerHTML = `
      <div class="result-score" style="color: ${scoreColor}">
        ${lastScan.categoryIcon || '📧'} ${lastScan.riskLevel} — Score: ${lastScan.score}/100
      </div>
      <div class="risk-gauge-container">
        <div class="risk-gauge-label">
          <span>Risk</span><span>${lastScan.score}%</span>
        </div>
        <div class="risk-gauge-bar">
          <div class="risk-gauge-fill ${gaugeClass}" style="width:${lastScan.score}%;"></div>
        </div>
      </div>
      <div class="result-category">${lastScan.category || 'General'}</div>
      <div class="result-flags">
        ${detailsHtml}
      </div>
      <div style="font-size:11px;color:#64748b;margin-top:6px;">
        ${timeAgo(lastScan.timestamp)}
      </div>
    `;

    // show educational tip
    const tipDiv = document.getElementById('educationalTip');
    if (lastScan.explanation?.educationalTips && lastScan.explanation.educationalTips.length > 0) {
      tipDiv.innerHTML = `<h4>💡 Tip</h4><p>${lastScan.explanation.educationalTips[0]}</p>`;
      tipDiv.style.display = 'block';
    }

    section.style.display = 'block';

    // allow clicking flags to show/hide details (if explanation included)
    resultDiv.querySelectorAll('.flag-item').forEach(item => {
      item.addEventListener('click', () => {
        item.classList.toggle('expanded');
      });
    });
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

  // Help modal button
  document.getElementById('helpBtn').addEventListener('click', () => {
    document.getElementById('helpModal').classList.add('active');
  });

  document.getElementById('modalCloseBtn').addEventListener('click', () => {
    document.getElementById('helpModal').classList.remove('active');
  });
}



// explain flag codes
function getFlagExplanation(code) {
  const map = {
    URGENCY: 'Pressure to act quickly is a common scam tactic; pause and verify before replying.',
    THREAT: 'Scammers often use threats of arrest, fines, or service disconnection to scare you.',
    FINANCIAL: 'Mentions of money, debt, or refunds can be lures to get you to click malicious links.',
    IMPERSONATION: 'Generic greetings or names of large companies used to pretend legitimacy.',
    ACTION: 'Requests that you take a specific action (e.g., click a link) are often phishing attempts.',
    HINGLISH: 'Use of mixed Hindi/English is a pattern seen in regional scams.',
    GRAMMAR: 'Bad grammar or spelling mistakes are common in scam emails sent at scale.',
    CAPS: 'Excessive capital letters are used to create urgency or excitement.',
    PUNCTUATION: 'Too many exclamation/question marks usually indicate a scam-like tone.',
    DOMAIN_MISMATCH: 'Mentioning a brand but using a different sender domain is deceptive.'
  };
  return map[code] || null;
}

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
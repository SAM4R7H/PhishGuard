/**
 * ============================================
 * CONTENT.JS — Gmail DOM Interaction
 * Role: Extension Architect
 * Purpose: Detect email opens, extract content,
 * inject warning banners into Gmail
 * ============================================
 */

// ==========================================
// UI ARCHITECT FEATURE: Global Status Banner
// ==========================================
window.addEventListener("load", function () {
  if (window.location.hostname.includes("mail.google.com")) {
    
    // Check if it already exists so we don't create duplicates
    if (document.getElementById("phishguard-global-status")) return;

    const topBanner = document.createElement("div");
    topBanner.id = "phishguard-global-status";
    topBanner.innerText = "🛡 PhishGuard is Active";

    // Nidhi's Styling, upgraded by the Lead to a modern floating pill
    topBanner.style.position = "fixed";      
    topBanner.style.bottom = "24px";         
    topBanner.style.left = "24px";           
    topBanner.style.padding = "8px 16px";
    topBanner.style.backgroundColor = "#16a34a"; 
    topBanner.style.color = "white";
    topBanner.style.textAlign = "center";
    topBanner.style.zIndex = "999999";
    topBanner.style.fontWeight = "bold";
    topBanner.style.borderRadius = "20px";   
    topBanner.style.boxShadow = "0 4px 12px rgba(0,0,0,0.15)"; 
    topBanner.style.fontSize = "13px";
    topBanner.style.fontFamily = "'Google Sans', Roboto, Arial, sans-serif";
    topBanner.style.letterSpacing = "0.3px";

    document.body.appendChild(topBanner);
  }
});

(function () {
  "use strict";

  // ── State ──
  let lastScannedEmailId = null;
  let observer = null;
  let isInitialized = false;

  function init() {
    if (isInitialized) return;
    isInitialized = true;
    PhishGuardHelpers.log("Content script loaded on " + window.location.hostname);
    waitForGmail(() => {
      PhishGuardHelpers.log("Gmail detected — starting observer");
      startObserver();
    });
  }

  function waitForGmail(callback, maxAttempts = 50) {
    let attempts = 0;
    const check = setInterval(() => {
      attempts++;
      const mainContent = document.querySelector('div[role="main"]');
      if (mainContent) {
        clearInterval(check);
        callback();
      } else if (attempts >= maxAttempts) {
        clearInterval(check);
      }
    }, 500);
  }

  function startObserver() {
    const targetNode = document.querySelector('div[role="main"]') || document.body;
    observer = new MutationObserver(
      PhishGuardHelpers.debounce((mutations) => {
        handleDOMChange();
      }, 800)
    );
    observer.observe(targetNode, { childList: true, subtree: true });
    handleDOMChange();
  }

  async function handleDOMChange() {
    const emailData = extractEmailData();
    if (!emailData) return;

    const emailId = simpleHash(emailData.body.substring(0, 200));
    if (emailId === lastScannedEmailId) return;
    lastScannedEmailId = emailId;

    PhishGuardHelpers.log("New email detected — scanning...");
    const result = await PhishAIEngine.analyze(emailData);

    injectWarningBanner(result);

    // LEAD RESOLUTION: Keep the safe background storage message, discard direct save.
    chrome.runtime.sendMessage({
      type: "SAVE_RESULT",
      payload: result
    });

    try {
      chrome.runtime.sendMessage({
        type: "SCAN_COMPLETE",
        payload: result
      }).catch(() => { }); 
    } catch (e) { }
  }

  function extractEmailData() {
    const emailSelectors = [
      'div.a3s.aiL', 'div[data-message-id] div.a3s', 
      'div.ii.gt div.a3s', 'div[role="listitem"] div.a3s',
    ];

    let emailBody = null;
    for (const selector of emailSelectors) {
      const elements = document.querySelectorAll(selector);
      if (elements.length > 0) {
        emailBody = elements[elements.length - 1];
        break;
      }
    }

    if (!emailBody) return null;

    const bodyText = PhishGuardHelpers.cleanText(emailBody.innerText || "");
    if (bodyText.length < 10) return null; 

    const linkElements = emailBody.querySelectorAll('a[href]');
    const urls = Array.from(linkElements).map(a => a.href).filter(href => href.startsWith('http'));

    const senderInfo = extractSenderInfo();
    const subjectEl = document.querySelector('h2[data-thread-perm-id]') || document.querySelector('div.ha h2') || document.querySelector('h2.hP');
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    return {
      body: bodyText,
      urls: [...new Set(urls)],
      sender: senderInfo.email,
      displayName: senderInfo.name,
      subject
    };
  }

  function extractSenderInfo() {
    const result = { email: "", name: "" };
    const senderSelectors = ['span[email]', 'span.gD', 'span.go', 'table.cf.gJ span[email]'];
    for (const selector of senderSelectors) {
      const el = document.querySelector(selector);
      if (el) {
        result.email = el.getAttribute('email') || "";
        result.name = el.getAttribute('name') || el.innerText || "";
        if (result.email) break;
      }
    }
    return result;
  }

  function injectWarningBanner(result) {
    const existing = document.getElementById('phishguard-banner');
    if (existing) existing.remove();

    if (result.score < 15) return;

    const emailContainer = document.querySelector('div.a3s.aiL')?.closest('div[data-message-id]') || document.querySelector('div.a3s.aiL')?.parentElement?.parentElement;
    if (!emailContainer) return;

    const banner = document.createElement('div');
    banner.id = 'phishguard-banner';
    banner.style.cssText = `
      margin: 8px 0 12px 0; padding: 14px 18px; border-radius: 12px;
      font-family: 'Google Sans', Roboto, Arial, sans-serif; font-size: 14px;
      line-height: 1.5; border: 1px solid; animation: phishguardSlideIn 0.3s ease-out;
      position: relative; z-index: 1;
    `;

    if (result.score >= 70) {
      banner.style.backgroundColor = '#fef2f2'; banner.style.borderColor = '#fca5a5'; banner.style.color = '#991b1b';
    } else if (result.score >= 30) {
      banner.style.backgroundColor = '#fffbeb'; banner.style.borderColor = '#fcd34d'; banner.style.color = '#92400e';
    } else {
      banner.style.backgroundColor = '#f0fdf4'; banner.style.borderColor = '#86efac'; banner.style.color = '#166534';
    }

    banner.innerHTML = buildBannerContent(result);

    if (!document.getElementById('phishguard-styles')) {
      const style = document.createElement('style');
      style.id = 'phishguard-styles';
      style.textContent = `
        @keyframes phishguardSlideIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        #phishguard-banner .pg-details { display: none; margin-top: 10px; }
        #phishguard-banner .pg-details.open { display: block; }
        #phishguard-banner .pg-toggle { cursor: pointer; text-decoration: underline; font-weight: 500; background: none; border: none; color: inherit; font-size: 13px; padding: 0; margin-left: 12px; }
        #phishguard-banner .pg-flag { padding: 3px 0; font-size: 13px; }
        #phishguard-banner .pg-tip { margin-top: 8px; padding: 8px 12px; background: rgba(0,0,0,0.05); border-radius: 6px; font-size: 12px; font-style: italic; }
        #phishguard-banner .pg-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; }
        #phishguard-banner .pg-score-badge { font-weight: 700; font-size: 13px; padding: 2px 10px; border-radius: 20px; display: inline-block; }
        #phishguard-banner .pg-close { position: absolute; top: 8px; right: 12px; cursor: pointer; background: none; border: none; font-size: 18px; color: inherit; opacity: 0.6; line-height: 1; }
        #phishguard-banner .pg-close:hover { opacity: 1; }
      `;
      document.head.appendChild(style);
    }

    emailContainer.insertBefore(banner, emailContainer.firstChild);

    const toggleBtn = banner.querySelector('.pg-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const details = banner.querySelector('.pg-details');
        details.classList.toggle('open');
        toggleBtn.textContent = details.classList.contains('open') ? 'Hide details' : 'Why?';
      });
    }

    const closeBtn = banner.querySelector('.pg-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        banner.style.animation = 'none'; banner.style.opacity = '0'; banner.style.transition = 'opacity 0.2s';
        setTimeout(() => banner.remove(), 200);
      });
    }
  }

  function buildBannerContent(result) {
    if (!result || !result.explanation) return '';

    const { explanation, score, categoryIcon, category, details } = result;
    const scoreBadgeColor = score >= 70 ? 'background:#fee2e2;color:#dc2626' : score >= 30 ? 'background:#fef3c7;color:#d97706' : 'background:#dcfce7;color:#16a34a';

    let flagsHTML = '';
    if (explanation.details && Array.isArray(explanation.details) && explanation.details.length > 0) {
      flagsHTML = explanation.details
        // LEAD FIX: Handle both Nikhil's Objects and legacy strings
        .map(flag => {
          const flagText = typeof flag === 'object' ? (flag.message || "Suspicious indicator") : flag;
          return `<div class="pg-flag">• ${flagText}</div>`;
        })
        .join('');
    }

    let tipText = "Stay vigilant online.";
    if (Array.isArray(explanation.educationalTips) && explanation.educationalTips.length > 0) {
      tipText = explanation.educationalTips.join(' ');
    }

    return `
      <button class="pg-close" title="Dismiss">×</button>
      <div class="pg-header">
        <div><strong>${categoryIcon || '📧'} PhishGuard:</strong> ${explanation.summary || 'Analysis Complete'} <button class="pg-toggle">Why?</button></div>
        <span class="pg-score-badge" style="${scoreBadgeColor}">Score: ${score}/100</span>
      </div>
      <div class="pg-details">
        <div style="margin-bottom:6px;font-weight:600;font-size:13px;">🔍 What we found:</div>
        ${flagsHTML}
        <div style="margin-top:8px;font-size:12px;opacity:0.8;">📊 Breakdown — Text: ${details?.textScore || 0} | URLs: ${details?.urlScore || 0} | Sender: ${details?.senderScore || 0}</div>
        <div class="pg-tip">💡 <strong>Tip:</strong> ${tipText}</div>
      </div>
    `;
  }

  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return hash.toString(36);
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "MANUAL_SCAN") {
      lastScannedEmailId = null; 
      handleDOMChange();
      sendResponse({ status: "scanning" });
    }
    if (message.type === "GET_CURRENT_STATUS") {
      sendResponse({ isActive: isInitialized, lastScanId: lastScannedEmailId });
    }
    return true;
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
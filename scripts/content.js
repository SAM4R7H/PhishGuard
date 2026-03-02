/**
 * ============================================
 * CONTENT.JS — Gmail DOM Interaction
 * Role: Extension Architect
 * Purpose: Detect email opens, extract content,
 * inject warning banners into Gmail
 * ============================================
 */

(function () {
  "use strict";

  // ── State ──
  let lastScannedEmailId = null;
  let observer = null;
  let isInitialized = false;

  // ══════════════════════════════════════════
  //  INITIALIZATION
  // ══════════════════════════════════════════

  function init() {
    if (isInitialized) return;
    isInitialized = true;

    PhishGuardHelpers.log("Content script loaded on " + window.location.hostname);

    // Wait for Gmail to fully load
    waitForGmail(() => {
      PhishGuardHelpers.log("Gmail detected — starting observer");
      startObserver();
    });
  }

  /**
   * Wait until Gmail's main content is available
   */
  function waitForGmail(callback, maxAttempts = 50) {
    let attempts = 0;
    const check = setInterval(() => {
      attempts++;
      // Gmail's main role="main" container
      const mainContent = document.querySelector('div[role="main"]');
      if (mainContent) {
        clearInterval(check);
        callback();
      } else if (attempts >= maxAttempts) {
        clearInterval(check);
        PhishGuardHelpers.log("Gmail main content not found after max attempts");
      }
    }, 500);
  }

  // ══════════════════════════════════════════
  //  MUTATION OBSERVER — Detect Email Opens
  // ══════════════════════════════════════════

  function startObserver() {
    const targetNode = document.querySelector('div[role="main"]') || document.body;

    observer = new MutationObserver(
      PhishGuardHelpers.debounce((mutations) => {
        handleDOMChange();
      }, 800)
    );

    observer.observe(targetNode, {
      childList: true,
      subtree: true,
    });

    PhishGuardHelpers.log("MutationObserver active");

    // Also scan if an email is already open
    handleDOMChange();
  }

  /**
   * Called on every significant DOM change
   * Checks if a new email is open
   */
   async function handleDOMChange() {
    const emailData = extractEmailData();

    if (!emailData) return;

    // Generate a simple ID to avoid re-scanning same email
    const emailId = simpleHash(emailData.body.substring(0, 200));

    if (emailId === lastScannedEmailId) return;
    lastScannedEmailId = emailId;

    PhishGuardHelpers.log("New email detected — scanning...");

    // Run AI analysis
    const result = await PhishAIEngine.analyze(emailData);

    // Inject the warning banner
    injectWarningBanner(result);

    // Send result to background for storage
    chrome.runtime.sendMessage({
      type: "SAVE_RESULT",
      payload: result
    });

    // Notify background script (safely)
    try {
      chrome.runtime.sendMessage({
        type: "SCAN_COMPLETE",
        payload: result
      }).catch(() => {}); // Ignore if popup isn't open
    } catch (e) {
      // Extension context invalidated usually
    }
  }

  // ══════════════════════════════════════════
  //  EMAIL DATA EXTRACTION
  // ══════════════════════════════════════════

  function extractEmailData() {
    // ── Try to find the open email body ──
    // Gmail uses multiple possible selectors
    const emailSelectors = [
      'div.a3s.aiL',                          // Standard email body
      'div[data-message-id] div.a3s',         // Alternative
      'div.ii.gt div.a3s',                    // Another variant
      'div[role="listitem"] div.a3s',         // Conversation view
    ];

    let emailBody = null;
    for (const selector of emailSelectors) {
      const elements = document.querySelectorAll(selector);
      if (elements.length > 0) {
        // Get the last (most recent) email in conversation
        emailBody = elements[elements.length - 1];
        break;
      }
    }

    if (!emailBody) return null;

    // ── Extract text content ──
    const bodyText = PhishGuardHelpers.cleanText(emailBody.innerText || "");
    if (bodyText.length < 10) return null; // Too short to analyze

    // ── Extract URLs ──
    const linkElements = emailBody.querySelectorAll('a[href]');
    const urls = Array.from(linkElements)
      .map(a => a.href)
      .filter(href => href.startsWith('http'));

    // ── Extract sender info ──
    const senderInfo = extractSenderInfo();

    // ── Extract subject ──
    const subjectEl = document.querySelector('h2[data-thread-perm-id]')
      || document.querySelector('div.ha h2')
      || document.querySelector('h2.hP');
    const subject = subjectEl ? subjectEl.innerText.trim() : "";

    return {
      body: bodyText,
      urls: [...new Set(urls)],
      sender: senderInfo.email,
      displayName: senderInfo.name,
      subject
    };
  }

  /**
   * Extract sender email and display name
   */
  function extractSenderInfo() {
    const result = { email: "", name: "" };

    // Try multiple Gmail sender selectors
    const senderSelectors = [
      'span[email]',                  // Has email attribute
      'span.gD',                      // Sender display name
      'span.go',                      // Alternative
      'table.cf.gJ span[email]',      // In header table
    ];

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

  // ══════════════════════════════════════════
  //  WARNING BANNER INJECTION
  // ══════════════════════════════════════════

  function injectWarningBanner(result) {
    // Remove any existing banner
    const existing = document.getElementById('phishguard-banner');
    if (existing) existing.remove();

    // Don't show banner for safe emails (optional: comment out to always show)
    if (result.score < 15) return;

    // Find insertion point (above the email body)
    const emailContainer =
      document.querySelector('div.a3s.aiL')?.closest('div[data-message-id]')
      || document.querySelector('div.a3s.aiL')?.parentElement?.parentElement;

    if (!emailContainer) {
      PhishGuardHelpers.log("Could not find email container for banner injection");
      return;
    }

    // ── Build Banner HTML ──
    const banner = document.createElement('div');
    banner.id = 'phishguard-banner';
    banner.style.cssText = `
      margin: 8px 0 12px 0;
      padding: 14px 18px;
      border-radius: 12px;
      font-family: 'Google Sans', Roboto, Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      border: 1px solid;
      animation: phishguardSlideIn 0.3s ease-out;
      position: relative;
      z-index: 1;
    `;

    // Color based on risk
    if (result.score >= 70) {
      banner.style.backgroundColor = '#fef2f2';
      banner.style.borderColor = '#fca5a5';
      banner.style.color = '#991b1b';
    } else if (result.score >= 30) {
      banner.style.backgroundColor = '#fffbeb';
      banner.style.borderColor = '#fcd34d';
      banner.style.color = '#92400e';
    } else {
      banner.style.backgroundColor = '#f0fdf4';
      banner.style.borderColor = '#86efac';
      banner.style.color = '#166534';
    }

    banner.innerHTML = buildBannerContent(result);

    // Inject animation keyframes
    if (!document.getElementById('phishguard-styles')) {
      const style = document.createElement('style');
      style.id = 'phishguard-styles';
      style.textContent = `
        @keyframes phishguardSlideIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        #phishguard-banner .pg-details { display: none; margin-top: 10px; }
        #phishguard-banner .pg-details.open { display: block; }
        #phishguard-banner .pg-toggle {
          cursor: pointer; text-decoration: underline;
          font-weight: 500; background: none; border: none;
          color: inherit; font-size: 13px; padding: 0; margin-left: 12px;
        }
        #phishguard-banner .pg-flag {
          padding: 3px 0; font-size: 13px;
        }
        #phishguard-banner .pg-tip {
          margin-top: 8px; padding: 8px 12px;
          background: rgba(0,0,0,0.05); border-radius: 6px;
          font-size: 12px; font-style: italic;
        }
        #phishguard-banner .pg-header {
          display: flex; align-items: center;
          justify-content: space-between; flex-wrap: wrap;
        }
        #phishguard-banner .pg-score-badge {
          font-weight: 700; font-size: 13px;
          padding: 2px 10px; border-radius: 20px;
          display: inline-block;
        }
        #phishguard-banner .pg-close {
          position: absolute; top: 8px; right: 12px;
          cursor: pointer; background: none; border: none;
          font-size: 18px; color: inherit; opacity: 0.6;
          line-height: 1;
        }
        #phishguard-banner .pg-close:hover { opacity: 1; }
      `;
      document.head.appendChild(style);
    }

    // Insert banner before the email
    emailContainer.insertBefore(banner, emailContainer.firstChild);

    // Event listeners
    const toggleBtn = banner.querySelector('.pg-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const details = banner.querySelector('.pg-details');
        details.classList.toggle('open');
        toggleBtn.textContent = details.classList.contains('open')
          ? 'Hide details'
          : 'Why?';
      });
    }

    const closeBtn = banner.querySelector('.pg-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        banner.style.animation = 'none';
        banner.style.opacity = '0';
        banner.style.transition = 'opacity 0.2s';
        setTimeout(() => banner.remove(), 200);
      });
    }
  }

  /**
   * Build the inner HTML for the warning banner
   */
  function buildBannerContent(result) {
    // 1. FAIL-SAFE: Prevent crashes if AI fails
    if (!result || !result.explanation) return '';

    const { explanation, score, categoryIcon, category, details } = result;

    const scoreBadgeColor = score >= 70
      ? 'background:#fee2e2;color:#dc2626'
      : score >= 30
        ? 'background:#fef3c7;color:#d97706'
        : 'background:#dcfce7;color:#16a34a';

    // 2. Safely map flags
    let flagsHTML = '';
    if (explanation.details && Array.isArray(explanation.details) && explanation.details.length > 0) {
      flagsHTML = explanation.details
        .map(flag => `<div class="pg-flag">• ${flag}</div>`)
        .join('');
    }

    // 3. Handle Nikhil's change from string to Array for educational tips
    let tipText = "Stay vigilant online.";
    if (Array.isArray(explanation.educationalTips) && explanation.educationalTips.length > 0) {
      tipText = explanation.educationalTips.join(' ');
    }

    return `
      <button class="pg-close" title="Dismiss">×</button>
      <div class="pg-header">
        <div>
          <strong>${categoryIcon || '📧'} PhishGuard:</strong> ${explanation.summary || 'Analysis Complete'}
          <button class="pg-toggle">Why?</button>
        </div>
        <span class="pg-score-badge" style="${scoreBadgeColor}">
          Score: ${score}/100
        </span>
      </div>
      <div class="pg-details">
        <div style="margin-bottom:6px;font-weight:600;font-size:13px;">
          🔍 What we found:
        </div>
        ${flagsHTML}
        <div style="margin-top:8px;font-size:12px;opacity:0.8;">
          📊 Breakdown — Text: ${details?.textScore || 0} | URLs: ${details?.urlScore || 0} | Sender: ${details?.senderScore || 0}
        </div>
        <div class="pg-tip">
          💡 <strong>Tip:</strong> ${tipText}
        </div>
      </div>
    `;
  }

  // ══════════════════════════════════════════
  //  UTILITY
  // ══════════════════════════════════════════

  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return hash.toString(36);
  }

  // ══════════════════════════════════════════
  //  LISTEN FOR MESSAGES FROM POPUP/BACKGROUND
  // ══════════════════════════════════════════

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "MANUAL_SCAN") {
      lastScannedEmailId = null; // Force re-scan
      handleDOMChange();
      sendResponse({ status: "scanning" });
    }

    if (message.type === "GET_CURRENT_STATUS") {
      sendResponse({
        isActive: isInitialized,
        lastScanId: lastScannedEmailId
      });
    }

    return true;
  });

  // ── Start ──
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
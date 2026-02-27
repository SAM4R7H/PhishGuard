/**
 * ============================================
 * HELPERS.JS — Shared Utility Functions
 * Purpose: Common functions used across all
 * extension components
 * ============================================
 */

const PhishGuardHelpers = {

  /**
   * Extract all URLs from a text string
   */
  extractURLs(text) {
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
    const matches = text.match(urlRegex);
    return matches ? [...new Set(matches)] : [];
  },

  /**
   * Extract email addresses from text
   */
  extractEmails(text) {
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const matches = text.match(emailRegex);
    return matches ? [...new Set(matches)] : [];
  },

  /**
   * Extract domain from URL
   */
  getDomain(url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname.toLowerCase();
    } catch {
      return null;
    }
  },

  /**
   * Clean text: remove extra whitespace, HTML tags
   */
  cleanText(text) {
    return text
      .replace(/<[^>]*>/g, ' ')        // Remove HTML tags
      .replace(/&nbsp;/g, ' ')         // Replace &nbsp;
      .replace(/\s+/g, ' ')            // Collapse whitespace
      .trim();
  },

  /**
   * PRIVACY SHIELD: Redact PII (Personal Identifiable Information)
   * Replaces emails, phones, and names with generic placeholders.
   */
  anonymizeText(text) {
    if (!text) return "";

    return text
      // 1. Redact Email Addresses
      .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
      
      // 2. Redact Phone Numbers (Generic 10-digit or international formats)
      // Matches: +91 9876543210, 987-654-3210, (123) 456-7890
      .replace(/(?:\+?\d{1,3}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}/g, '[REDACTED_PHONE]')
      
      // 3. Redact Credit Card Numbers (Groups of 4 digits)
      // Matches: 1234 5678 1234 5678
      .replace(/\b(?:\d{4}[ -]?){3}\d{4}\b/g, '[REDACTED_CARD]')
      
      // 4. Redact potential names after greetings
      // Matches: "Dear Samarth," -> "Dear [REDACTED_NAME],"
      .replace(/(Hi|Hello|Dear)\s+([A-Z][a-z]+)/g, '$1 [REDACTED_NAME]');
  },

  /**
   * Calculate Levenshtein distance between two strings
   * Used for typosquatting detection
   */
  levenshteinDistance(str1, str2) {
    const m = str1.length;
    const n = str2.length;
    const dp = Array(m + 1).fill(null)
      .map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,        // deletion
          dp[i][j - 1] + 1,        // insertion
          dp[i - 1][j - 1] + cost  // substitution
        );
      }
    }
    return dp[m][n];
  },

  /**
   * Format risk score into human-readable result
   */
  formatRiskResult(score) {
    const { RISK_LEVELS } = SCAM_CONSTANTS;
    if (score <= RISK_LEVELS.SAFE.max) {
      return { ...RISK_LEVELS.SAFE, score };
    } else if (score <= RISK_LEVELS.CAUTION.max) {
      return { ...RISK_LEVELS.CAUTION, score };
    } else {
      return { ...RISK_LEVELS.DANGER, score };
    }
  },

  /**
   * Generate unique ID for each scan
   */
  generateScanId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  },

  /**
   * Debounce function to prevent excessive scanning
   */
  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },

  /**
   * Safe console log with extension prefix
   */
  log(message, data = null) {
    const prefix = "[PhishGuard]";
    if (data) {
      console.log(`${prefix} ${message}`, data);
    } else {
      console.log(`${prefix} ${message}`);
    }
  },

  /**
   * Store scan result to chrome.storage
   */
  async saveScanResult(result) {
    try {
      const data = await chrome.storage.local.get(['scanHistory', 'stats']);
      
      const history = data.scanHistory || [];
      const stats = data.stats || {
        totalScans: 0,
        scamsDetected: 0,
        safeEmails: 0,
        categoryCounts: {}
      };

      // === FIX: Ensure categoryCounts exists (Self-Healing) ===
      if (!stats.categoryCounts) {
        stats.categoryCounts = {};
      }

      // Add to history (keep last 100)
      history.unshift({
        ...result,
        timestamp: Date.now()
      });
      if (history.length > 100) history.pop();

      // Update stats
      stats.totalScans++;
      
      if (result.score >= 70) {
        stats.scamsDetected++;
      } else {
        stats.safeEmails++;
      }
      
      if (result.category) {
        stats.categoryCounts[result.category] =
          (stats.categoryCounts[result.category] || 0) + 1;
      }

      await chrome.storage.local.set({ scanHistory: history, stats });
      
    } catch (error) {
      // Use console.error so it stands out, but don't break the app
      console.error("[PhishGuard] Storage Error:", error);
    }
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishGuardHelpers;
}
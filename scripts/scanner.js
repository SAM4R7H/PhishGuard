/**
 * ============================================
 * SCANNER.JS — URL & Sender Analysis Engine
 * Role: Cyber-Analyst
 * Purpose: Analyze URLs and sender info for
 * phishing indicators
 * ============================================
 */

const PhishScanner = {

  /**
   * ─── MAIN: Analyze a URL for phishing indicators ───
   * Returns: { score: 0-100, flags: [...reasons] }
   */
  analyzeURL(url) {
    const result = { score: 0, flags: [] };

    if (!url) return result;

    const domain = PhishGuardHelpers.getDomain(url);
    if (!domain) {
      result.score = 50;
      result.flags.push("Invalid or malformed URL");
      return result;
    }

    // Check 1: Is it a trusted domain?
    if (this._isTrustedDomain(domain)) {
      return { score: 0, flags: ["Verified trusted domain"] };
    }

    // Check 2: IP address instead of domain name
    if (SCAM_CONSTANTS.URL_RED_FLAGS.IP_ADDRESS.test(url)) {
      result.score += 40;
      result.flags.push("Uses IP address instead of domain name");
    }

    // Check 3: Suspicious TLD
    const tld = "." + domain.split(".").pop();
    if (SCAM_CONSTANTS.SUSPICIOUS_TLDS.includes(tld)) {
      result.score += 25;
      result.flags.push(`Suspicious domain extension: ${tld}`);
    }

    // Check 4: Excessive subdomains
    const subdomainCount = domain.split(".").length - 2;
    if (subdomainCount >= 3) {
      result.score += 20;
      result.flags.push(`Excessive subdomains (${subdomainCount} levels deep)`);
    }

    // Check 5: Typosquatting detection
    const typosquatResult = this._checkTyposquatting(domain);
    if (typosquatResult.isTyposquat) {
      result.score += 35;
      result.flags.push(
        `Possible typosquatting: looks like "${typosquatResult.intendedDomain}"`
      );
    }

    // Check 6: URL shortener
    if (this._isURLShortener(domain)) {
      result.score += 15;
      result.flags.push("URL shortener detected — destination hidden");
    }

    // Check 7: Suspicious path keywords
    if (SCAM_CONSTANTS.URL_RED_FLAGS.SUSPICIOUS_PATHS.test(url)) {
      result.score += 15;
      result.flags.push("URL path contains login/verification keywords");
    }

    // Check 8: @ symbol in URL (credential harvesting trick)
    if (SCAM_CONSTANTS.URL_RED_FLAGS.AT_SYMBOL.test(url)) {
      result.score += 30;
      result.flags.push("Contains @ symbol — may redirect to different site");
    }

    // Check 9: Very long URL (common in phishing)
    if (url.length > 150) {
      result.score += 10;
      result.flags.push("Unusually long URL");
    }

    // Check 10: Encoded characters
    const encodedCount = (url.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encodedCount > 3) {
      result.score += 15;
      result.flags.push("Contains multiple encoded characters (obfuscation)");
    }

    // Cap at 100
    result.score = Math.min(result.score, 100);

    return result;
  },

  /**
   * ─── Analyze multiple URLs and return worst score ───
   */
  analyzeAllURLs(urls) {
    if (!urls || urls.length === 0) {
      return { score: 0, flags: [], urlCount: 0 };
    }

    let worstScore = 0;
    let allFlags = [];
    let flaggedURLs = [];

    urls.forEach(url => {
      const analysis = this.analyzeURL(url);
      if (analysis.score > 0) {
        flaggedURLs.push({ url: this._truncateURL(url), ...analysis });
      }
      if (analysis.score > worstScore) {
        worstScore = analysis.score;
      }
      allFlags = allFlags.concat(analysis.flags);
    });

    return {
      score: worstScore,
      flags: [...new Set(allFlags)],
      urlCount: urls.length,
      flaggedURLs
    };
  },

  /**
   * ─── Analyze sender email address ───
   */
  analyzeSender(senderEmail, displayName) {
    const result = { score: 0, flags: [] };

    if (!senderEmail) return result;

    const email = senderEmail.toLowerCase().trim();
    const domain = email.split("@")[1];

    if (!domain) {
      result.score = 30;
      result.flags.push("Invalid sender email format");
      return result;
    }

    // Check 1: Display name vs email mismatch
    if (displayName) {
      const mismatch = this._checkSenderMismatch(email, displayName);
      if (mismatch.isMismatch) {
        result.score += 30;
        result.flags.push(
          `Sender mismatch: displays as "${displayName}" but email is ${email}`
        );
      }
    }

    // Check 2: Free email pretending to be organization
    const freeProviders = [
      "gmail.com", "yahoo.com", "hotmail.com",
      "outlook.com", "aol.com", "mail.com",
      "protonmail.com", "yandex.com"
    ];
    if (freeProviders.includes(domain) && displayName) {
      const orgKeywords = [
        "bank", "paypal", "amazon", "microsoft",
        "apple", "google", "irs", "government",
        "support", "security", "admin"
      ];
      const lowerDisplay = displayName.toLowerCase();
      const pretending = orgKeywords.some(k => lowerDisplay.includes(k));
      if (pretending) {
        result.score += 35;
        result.flags.push(
          `"${displayName}" using free email (${domain}) — likely impersonation`
        );
      }
    }

    // Check 3: Suspicious TLD on sender domain
    const senderTLD = "." + domain.split(".").pop();
    if (SCAM_CONSTANTS.SUSPICIOUS_TLDS.includes(senderTLD)) {
      result.score += 20;
      result.flags.push(`Sender domain uses suspicious extension: ${senderTLD}`);
    }

    // Check 4: Numbers in sender domain (e.g., secure-bank123.com)
    const domainWithoutTLD = domain.split(".").slice(0, -1).join(".");
    if (/\d{3,}/.test(domainWithoutTLD)) {
      result.score += 15;
      result.flags.push("Sender domain contains excessive numbers");
    }

    // Check 5: Very long sender domain
    if (domain.length > 30) {
      result.score += 10;
      result.flags.push("Unusually long sender domain");
    }

    result.score = Math.min(result.score, 100);
    return result;
  },


  // ══════════════════════════════════════════
  //  PRIVATE HELPER METHODS
  // ══════════════════════════════════════════

  _isTrustedDomain(domain) {
    return SCAM_CONSTANTS.TRUSTED_DOMAINS.some(trusted => {
      return domain === trusted || domain.endsWith("." + trusted);
    });
  },

  _isURLShortener(domain) {
    const shorteners = [
      "bit.ly", "tinyurl.com", "t.co", "goo.gl",
      "ow.ly", "is.gd", "buff.ly", "adf.ly",
      "bl.ink", "lnkd.in", "rb.gy", "shorturl.at",
      "cutt.ly", "t.ly"
    ];
    return shorteners.includes(domain);
  },

  _checkTyposquatting(domain) {
    const domainBase = domain.split(".").slice(0, -1).join(".").toLowerCase();

    for (const [real, fakes] of Object.entries(SCAM_CONSTANTS.TYPOSQUAT_MAP)) {
      // Direct fake match
      if (fakes.some(f => domainBase.includes(f))) {
        return { isTyposquat: true, intendedDomain: real };
      }

      // Levenshtein distance check
      if (domainBase.includes(real.substring(0, 3))) {
        const distance = PhishGuardHelpers.levenshteinDistance(domainBase, real);
        if (distance > 0 && distance <= 2) {
          return { isTyposquat: true, intendedDomain: real };
        }
      }
    }

    return { isTyposquat: false };
  },

  _checkSenderMismatch(email, displayName) {
    const displayLower = displayName.toLowerCase().replace(/[^a-z]/g, '');
    const emailUser = email.split("@")[0].toLowerCase().replace(/[^a-z]/g, '');
    const emailDomain = email.split("@")[1].split(".")[0].toLowerCase();

    // Check if display name mentions a company but email doesn't match
    const companyNames = [
      "amazon", "paypal", "apple", "microsoft", "google",
      "netflix", "chase", "wells fargo", "bank of america",
      "sbi", "hdfc", "icici", "rbi"
    ];

    for (const company of companyNames) {
      const companyClean = company.replace(/\s/g, '');
      if (displayLower.includes(companyClean) && !emailDomain.includes(companyClean)) {
        return { isMismatch: true, company };
      }
    }

    return { isMismatch: false };
  },

  _truncateURL(url, maxLength = 60) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + "...";
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishScanner;
}
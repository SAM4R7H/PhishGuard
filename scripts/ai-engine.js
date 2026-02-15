/**
 * ============================================
 * AI-ENGINE.JS — Intelligence & Scoring Engine
 * Role: Intelligence Lead
 * Purpose: Analyze text content, score risk,
 * categorize scams, generate explanations
 * ============================================
 */

const PhishAIEngine = {

  /**
   * ─── MAIN ENTRY: Full analysis of email content ───
   * @param {Object} emailData - { body, sender, displayName, urls, subject }
   * @returns {Object} Complete scan result
   */
  analyze(emailData) {
    const scanId = PhishGuardHelpers.generateScanId();
    const startTime = performance.now();

    PhishGuardHelpers.log("Starting analysis", scanId);

    // Step 1: Text analysis
    const textResult = this.analyzeText(
      emailData.body,
      emailData.subject || ""
    );

    // Step 2: URL analysis
    const urlResult = PhishScanner.analyzeAllURLs(emailData.urls);

    // Step 3: Sender analysis
    const senderResult = PhishScanner.analyzeSender(
      emailData.sender,
      emailData.displayName
    );

    // Step 4: Calculate weighted score
    const weights = SCAM_CONSTANTS.SCORE_WEIGHTS;
    const finalScore = Math.round(
      (textResult.score * weights.TEXT) +
      (urlResult.score * weights.URL) +
      (senderResult.score * weights.SENDER)
    );

    // Step 5: Determine category
    const category = this._detectCategory(emailData.body);

    // Step 6: Generate explanation
    const explanation = this._generateExplanation(
      textResult, urlResult, senderResult, category
    );

    // Step 7: Build result
    const riskLevel = PhishGuardHelpers.formatRiskResult(finalScore);
    const processingTime = Math.round(performance.now() - startTime);

    const result = {
      scanId,
      score: finalScore,
      riskLevel: riskLevel.label,
      color: riskLevel.color,
      category: category ? category.label : "General",
      categoryIcon: category ? category.icon : "📧",
      explanation,
      details: {
        textScore: textResult.score,
        urlScore: urlResult.score,
        senderScore: senderResult.score,
        textFlags: textResult.flags,
        urlFlags: urlResult.flags,
        senderFlags: senderResult.flags,
        urlCount: urlResult.urlCount,
        flaggedURLs: urlResult.flaggedURLs || []
      },
      processingTime,
      timestamp: Date.now()
    };

    PhishGuardHelpers.log(`Analysis complete: Score ${finalScore}`, result);

    return result;
  },

  /**
   * ─── Text Content Analysis ───
   */
  analyzeText(body, subject = "") {
    const result = { score: 0, flags: [] };
    const fullText = `${subject} ${body}`.toLowerCase();

    if (!fullText.trim()) return result;

    // Check 1: Urgency keywords
    const urgencyMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.URGENCY_KEYWORDS
    );
    if (urgencyMatches.length > 0) {
      const points = Math.min(urgencyMatches.length * 12, 40);
      result.score += points;
      result.flags.push(
        `Urgency tactics detected: "${urgencyMatches.slice(0, 3).join('", "')}"`
      );
    }

    // Check 2: Threat keywords
    const threatMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.THREAT_KEYWORDS
    );
    if (threatMatches.length > 0) {
      const points = Math.min(threatMatches.length * 15, 40);
      result.score += points;
      result.flags.push(
        `Threatening language: "${threatMatches.slice(0, 3).join('", "')}"`
      );
    }

    // Check 3: Financial bait
    const financialMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.FINANCIAL_KEYWORDS
    );
    if (financialMatches.length > 0) {
      const points = Math.min(financialMatches.length * 10, 35);
      result.score += points;
      result.flags.push(
        `Financial bait detected: "${financialMatches.slice(0, 3).join('", "')}"`
      );
    }

    // Check 4: Impersonation patterns
    const impersonationMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.IMPERSONATION_KEYWORDS
    );
    if (impersonationMatches.length >= 2) {
      result.score += 15;
      result.flags.push("Uses generic impersonation language (e.g., 'Dear Customer')");
    }

    // Check 5: Action requests
    const actionMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.ACTION_KEYWORDS
    );
    if (actionMatches.length > 0) {
      const points = Math.min(actionMatches.length * 8, 25);
      result.score += points;
      result.flags.push(
        `Pushes you to act: "${actionMatches.slice(0, 2).join('", "')}"`
      );
    }

    // Check 6: Hinglish/Indian scam patterns
    const hinglishMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.HINGLISH_KEYWORDS
    );
    if (hinglishMatches.length > 0) {
      result.score += Math.min(hinglishMatches.length * 10, 30);
      result.flags.push(
        `Regional scam pattern detected: "${hinglishMatches.slice(0, 2).join('", "')}"`
      );
    }

    // Check 7: Grammar errors
    const grammarMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.GRAMMAR_INDICATORS
    );
    if (grammarMatches.length > 0) {
      result.score += Math.min(grammarMatches.length * 8, 20);
      result.flags.push("Contains common grammar errors found in scam emails");
    }

    // Check 8: Excessive capitalization
    const capsRatio = this._calculateCapsRatio(body);
    if (capsRatio > 0.3 && body.length > 50) {
      result.score += 10;
      result.flags.push("Excessive use of CAPITAL LETTERS (shouting tactic)");
    }

    // Check 9: Excessive exclamation/question marks
    const exclamationCount = (body.match(/!{2,}/g) || []).length;
    const questionCount = (body.match(/\?{2,}/g) || []).length;
    if (exclamationCount + questionCount >= 3) {
      result.score += 8;
      result.flags.push("Excessive punctuation (!! or ??) — common in scams");
    }

    // Cap score
    result.score = Math.min(result.score, 100);

    return result;
  },

  // ══════════════════════════════════════════
  //  CATEGORY DETECTION
  // ══════════════════════════════════════════

  _detectCategory(text) {
    if (!text) return null;
    const lowerText = text.toLowerCase();

    let bestCategory = null;
    let bestMatchCount = 0;

    for (const [key, cat] of Object.entries(SCAM_CONSTANTS.SCAM_CATEGORIES)) {
      const matchCount = cat.keywords.filter(kw => lowerText.includes(kw)).length;
      if (matchCount > bestMatchCount) {
        bestMatchCount = matchCount;
        bestCategory = cat;
      }
    }

    return bestMatchCount >= 2 ? bestCategory : null;
  },

  // ══════════════════════════════════════════
  //  EXPLANATION GENERATOR
  // ══════════════════════════════════════════

  _generateExplanation(textResult, urlResult, senderResult, category) {
    const allFlags = [
      ...textResult.flags,
      ...urlResult.flags,
      ...senderResult.flags
    ];

    if (allFlags.length === 0) {
      return {
        summary: "This message appears safe. No scam indicators detected.",
        details: [],
        educationalTip: "Always verify unexpected requests through official channels."
      };
    }

    const totalScore = Math.round(
      (textResult.score * 0.4) + (urlResult.score * 0.4) + (senderResult.score * 0.2)
    );

    let summary;
    if (totalScore >= 70) {
      summary = `⚠️ HIGH RISK: ${category ? category.label : "Potential Scam"} Detected`;
    } else if (totalScore >= 30) {
      summary = `⚡ CAUTION: Some suspicious elements found`;
    } else {
      summary = `✅ LOW RISK: Minor concerns detected`;
    }

    const educationalTips = {
      BANKING: "Real banks NEVER ask for passwords, PINs, or OTPs via email. Always log in directly through the official app or website.",
      DELIVERY: "Check your actual order history on the retailer's official site. Don't click tracking links from emails.",
      JOB: "Legitimate employers never ask for money upfront. Research the company independently before responding.",
      GOVERNMENT: "Government agencies communicate through official mail. They never threaten immediate arrest via email.",
      LOTTERY: "You can't win a lottery you never entered. This is always a scam.",
      ROMANCE: "Never send money to someone you've only met online, no matter how convincing their story.",
      TECH_SUPPORT: "Microsoft, Apple, and Google will never email you about viruses. This is a scam.",
      CRYPTO: "No legitimate investment guarantees returns. If it sounds too good to be true, it is."
    };

    const categoryKey = category
      ? Object.entries(SCAM_CONSTANTS.SCAM_CATEGORIES)
          .find(([k, v]) => v.label === category.label)?.[0]
      : null;

    return {
      summary,
      details: allFlags,
      educationalTip: categoryKey
        ? educationalTips[categoryKey]
        : "When in doubt, contact the organization directly using their official website or phone number — never use contact info from the suspicious message itself."
    };
  },

  // ══════════════════════════════════════════
  //  PRIVATE HELPERS
  // ══════════════════════════════════════════

  _findKeywordMatches(text, keywords) {
    return keywords.filter(keyword => text.includes(keyword.toLowerCase()));
  },

  _calculateCapsRatio(text) {
    if (!text || text.length === 0) return 0;
    const letters = text.replace(/[^a-zA-Z]/g, '');
    if (letters.length === 0) return 0;
    const caps = letters.replace(/[^A-Z]/g, '');
    return caps.length / letters.length;
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishAIEngine;
}

// Expose to window for console testing
window.PhishAIEngine = PhishAIEngine;
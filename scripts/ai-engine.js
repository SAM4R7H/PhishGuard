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

    // Step 4: Calculate weighted score (rebalance weights with calibration + adaptive thresholds)
    const calibratedText = PhishGuardHelpers.calibrateScore(textResult.score, "TEXT");
    const calibratedURL = PhishGuardHelpers.calibrateScore(urlResult.score, "URL");
    const calibratedSender = PhishGuardHelpers.calibrateScore(senderResult.score, "SENDER");

    // Load adaptive weights (per tenant or fallback to defaults)
    const weights = PhishGuardHelpers.getAdaptiveWeights(emailData.tenantId) || {
      TEXT: 0.35,
      URL: 0.40,
      SENDER: 0.25
    };

    const rawScore = (calibratedText * weights.TEXT) +
                     (calibratedURL * weights.URL) +
                     (calibratedSender * weights.SENDER);

    // Normalize to 0–100 scale
    const finalScore = Math.round(rawScore * 100);

    // Step 5: Determine category
    const category = this._detectCategory(emailData.body, textResult);

    // Step 6: Generate explanation (with structured reason codes)
    const explanation = this._generateExplanation(
      textResult,
      urlResult,
      senderResult,
      category
    );

    // Step 7: Build result (tenant-aware thresholds)
    const riskLevel = PhishGuardHelpers.formatRiskResult(finalScore, emailData.tenantId);
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
        textFlags: textResult.flags.map(f => ({ code: f.code, message: f.message })),
        urlFlags: urlResult.flags.map(f => ({ code: f.code, message: f.message })),
        senderFlags: senderResult.flags.map(f => ({ code: f.code, message: f.message })),
        urlCount: urlResult.urlCount,
        flaggedURLs: urlResult.flaggedURLs || []
      },
      processingTime,
      timestamp: Date.now()
    };

    // ✅ Improved logging: include component scores and flags
    PhishGuardHelpers.log(`Analysis complete: Score ${finalScore}`, {
      scanId,
      textScore: textResult.score,
      urlScore: urlResult.score,
      senderScore: senderResult.score,
      flags: result.details
    });

    return result;
  },

  /**
   * ─── Text Content Analysis ───
   */
  analyzeText(body, subject = "") {
    const result = { score: 0, flags: [] };
    
    // === PRIVACY SHIELD: Scrub data before analysis ===
    const cleanBody = PhishGuardHelpers.anonymizeText(body);
    const cleanSubject = PhishGuardHelpers.anonymizeText(subject);

    // Debug log to prove privacy works
    PhishGuardHelpers.log("Analyzing anonymized content:", cleanSubject);

    // Combine and lowercase for analysis
    const fullText = `${cleanSubject} ${cleanBody}`.toLowerCase();

    if (!fullText.trim()) return result;

    // Check 1: Urgency keywords
    const urgencyMatches = this._findKeywordMatches(
      fullText,
      SCAM_CONSTANTS.URGENCY_KEYWORDS
    );
    if (urgencyMatches.length > 0) {
      const points = Math.min(urgencyMatches.length * 12, 30);
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
      const points = Math.min(threatMatches.length * 15, 30);
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
      const points = Math.min(financialMatches.length * 10, 27);
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
      result.score += Math.min(hinglishMatches.length * 10, 20);
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
      result.score += Math.min(grammarMatches.length * 8, 10);
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
// ==============================================
// CATEGORY DETECTION (Improved & Robust)
// ==============================================
_detectCategory(
  text,
  textResult = { score: 0 },
  urlResult = { flags: [], score: 0 },
  senderResult = { flags: [], score: 0 }
) {
    if (!text) return null;
    const lowerText = text.toLowerCase();

    let bestCategory = null;
    let bestMatchScore = 0;

    for (const [key, cat] of Object.entries(SCAM_CONSTANTS.SCAM_CATEGORIES)) {
        // Weighted keyword + fuzzy matching
        const matchScore = cat.keywords.reduce((sum, kw) => {
            return PhishGuardHelpers.fuzzyMatch(lowerText, kw)
                ? sum + (cat.weights?.[kw] || 1)
                : sum;
        }, 0);

        // Tie-breaking: prefer higher severity if scores equal
        if (
            matchScore > bestMatchScore ||
            (matchScore === bestMatchScore &&
             cat.severity > (bestCategory?.severity || 0))
        ) {
            bestMatchScore = matchScore;
            bestCategory = {
                ...cat,
                matchedKeywords: cat.keywords.filter(kw =>
                    PhishGuardHelpers.fuzzyMatch(lowerText, kw)
                ),
                matchScore
            };
        }
    }

    if (!bestCategory) return null;

    // Adaptive threshold per category severity
    const threshold = bestCategory.minMatch || 2;

    // Multi-signal boost: if URL or sender flags exist, lower threshold
    const hasExtraSignals =
        (urlResult.flags && urlResult.flags.length > 0) ||
        (senderResult.flags && senderResult.flags.length > 0);

    const effectiveThreshold = hasExtraSignals ? threshold - 1 : threshold;

    // Threshold logic: allow 1 keyword if text score is already high
    if (
        bestMatchScore >= effectiveThreshold ||
        (bestMatchScore === 1 && textResult.score >= 50)
    ) {
        return {
            ...bestCategory,
            confidence: bestMatchScore / bestCategory.keywords.length,
            signals: {
                textScore: textResult.score,
                urlScore: urlResult.score,
                senderScore: senderResult.score,
                urlFlags: urlResult.flags,
                senderFlags: senderResult.flags
            }
        };
    }

    return null;
},
 // ==============================================
// EXPLANATION GENERATOR (Improved & Robust)
// ==============================================
_generateExplanation(textResult, urlResult, senderResult, category) {
    const allFlags = [
      ...textResult.flags,
      ...urlResult.flags,
      ...senderResult.flags
    ];

    // If no flags at all
    if (allFlags.length === 0) {
      return {
        summary: "✅ SAFE: No scam indicators detected.",
        details: [],
        educationalTips: [
          "Always verify unexpected requests through official channels."
        ],
        metadata: {
          textScore: textResult.score,
          urlScore: urlResult.score,
          senderScore: senderResult.score,
          categoryConfidence: category?.confidence || null
        }
      };
    }

    // Weighted total score
    const totalScore = Math.round(
      (textResult.score * 0.4) +
      (urlResult.score * 0.4) +
      (senderResult.score * 0.2)
    );

    // Risk level logic: require non-text signals for HIGH RISK
    const hasStrongNonTextSignals = urlResult.score > 20 || senderResult.score > 15;
    const severityBoost = category?.severity || 0;
    const adjustedScore = totalScore + severityBoost * 10;

    let summary;
    if (adjustedScore >= 70 && hasStrongNonTextSignals) {
      summary = `⚠️ HIGH RISK: ${category ? category.label : "Potential Scam"} Detected`;
    } else if (adjustedScore >= 70) {
      summary = `⚡ CAUTION: Suspicious text patterns detected, but no strong sender/URL evidence`;
    } else if (adjustedScore >= 30) {
      summary = `⚡ CAUTION: Some suspicious elements found`;
    } else {
      summary = `✅ LOW RISK: Minor concerns detected`;
    }

    // Flag-based educational tips (structured flag codes preferred)
    const flagTips = [];
    if (textResult.flags.some(f => f.code === "URGENCY")) {
      flagTips.push("Scammers often pressure you with urgency. Pause and verify before acting.");
    }
    if (textResult.flags.some(f => f.code === "THREAT")) {
      flagTips.push("Threatening language is a scare tactic. Legitimate organizations don’t threaten arrest or fines via email.");
    }
    if (urlResult.flags.some(f => f.code === "SUSPICIOUS_URL")) {
      flagTips.push("Hover over links to check the real domain before clicking.");
    }
    if (senderResult.flags.some(f => f.code === "MISMATCH")) {
      flagTips.push("Sender address doesn’t match display name — a common impersonation trick.");
    }

    // Category-specific educational tips
    const educationalTipsMap = {
      BANKING: "Real banks NEVER ask for passwords, PINs, or OTPs via email.",
      DELIVERY: "Check your actual order history on the retailer's official site.",
      JOB: "Legitimate employers never ask for money upfront.",
      GOVERNMENT: "Government agencies never threaten immediate arrest via email.",
      LOTTERY: "You can't win a lottery you never entered.",
      ROMANCE: "Never send money to someone you've only met online.",
      TECH_SUPPORT: "Microsoft, Apple, and Google will never email you about viruses.",
      CRYPTO: "No legitimate investment guarantees returns."
    };

    const categoryKey = category
      ? Object.entries(SCAM_CONSTANTS.SCAM_CATEGORIES)
          .find(([k, v]) => v.label === category.label)?.[0]
      : null;

    return {
      summary,
      details: [
        ...allFlags.map(f => f.message || f), // prefer structured flag messages
        ...(category?.matchedKeywords
          ? [`Category keywords: ${category.matchedKeywords.join(", ")}`]
          : [])
      ],
      educationalTips: flagTips.length > 0
        ? flagTips
        : categoryKey
          ? [educationalTipsMap[categoryKey]]
          : ["When in doubt, contact the organization directly using their official website or phone number."],
      metadata: {
        textScore: textResult.score,
        urlScore: urlResult.score,
        senderScore: senderResult.score,
        categoryConfidence: category?.confidence || null,
        severity: category?.severity || null
      }
    };
},
  // ══════════════════════════════════════════
//  PRIVATE HELPERS (Improved)
// ══════════════════════════════════════════

_findKeywordMatches(text, keywords) {
  if (!text) return [];
  const lowerText = text.toLowerCase();

  // Use fuzzy matching helper if available, else fallback to includes
  return keywords.filter(keyword =>
    PhishGuardHelpers.fuzzyMatch
      ? PhishGuardHelpers.fuzzyMatch(lowerText, keyword.toLowerCase())
      : lowerText.includes(keyword.toLowerCase())
  );
},

_calculateCapsRatio(text) {
  if (!text || text.length < 5) {
    return { ratio: 0, totalLetters: 0, totalCaps: 0 };
  }

  const letters = text.replace(/[^a-zA-Z]/g, '');
  if (letters.length === 0) {
    return { ratio: 0, totalLetters: 0, totalCaps: 0 };
  }

  const caps = letters.replace(/[^A-Z]/g, '');
  const ratio = caps.length / letters.length;

  return {
    ratio,
    totalLetters: letters.length,
    totalCaps: caps.length
  };
}
};

// Universal module definition for safe export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishAIEngine;
} else if (typeof window !== 'undefined') {
  window.PhishAIEngine = PhishAIEngine;
}
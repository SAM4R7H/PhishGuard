/**
 * ============================================
 * AI-ENGINE.JS — Intelligence & Scoring Engine
 * Role: Intelligence Lead
 *
 * Purpose: Analyze text content, score risk,
 * categorize scams, generate explanations
 * ============================================
 */
let tf;
try {
  tf = require('@tensorflow/tfjs-node');
  if (typeof PhishGuardHelpers !== 'undefined' && PhishGuardHelpers.log) PhishGuardHelpers.log("✅ Using @tensorflow/tfjs-node");
} catch (err) {
  tf = require('@tensorflow/tfjs');
  if (typeof PhishGuardHelpers !== 'undefined' && PhishGuardHelpers.log) PhishGuardHelpers.log("⚠️ Falling back to @tensorflow/tfjs");
}

const path = require('path');

async function loadPhishingModel() {
  try {
    if (tf && tf.node) {
      const modelUrl = 'file://' + path.join(__dirname, '..', 'Models', 'phishingmodel', 'model.json');
      PhishAIEngine.phishingModel = await tf.loadLayersModel(modelUrl);
      if (typeof PhishGuardHelpers !== 'undefined' && PhishGuardHelpers.log) PhishGuardHelpers.log("Phishing model loaded successfully");
    } else {
      if (typeof PhishGuardHelpers !== 'undefined' && PhishGuardHelpers.log) PhishGuardHelpers.log("Skipping model load: @tensorflow/tfjs-node not present (file:// unsupported in pure JS backend)");
      PhishAIEngine.phishingModel = null;
    }
  } catch (err) {
    if (typeof PhishGuardHelpers !== 'undefined' && PhishGuardHelpers.log) PhishGuardHelpers.log('Failed to load phishing model:', err);
    PhishAIEngine.phishingModel = null;
  }
}
const PhishAIEngine = {

  /**
   * ─── MAIN ENTRY: Full analysis of email content ───
   * @param {Object} emailData - { body, sender, displayName, urls, subject, tenantId }
   * @returns {Object} Complete scan result
   */
  async analyze(emailData) {
    const scanId = PhishGuardHelpers.generateScanId();
    const startTime = performance.now();

    PhishGuardHelpers.log("Starting analysis", scanId);

    // Step 1: Text analysis
    const textResult = await this.analyzeText(
      emailData.body,
      emailData.subject || "",
      emailData.sender ? emailData.sender.split("@")[1] : "" // extract domain
    );

    // Step 2: URL analysis
    const urlResult = PhishScanner.analyzeAllURLs(emailData.urls);

    // Step 3: Sender analysis
    const senderResult = PhishScanner.analyzeSender(
      emailData.sender,
      emailData.displayName
    );

    // Step 4: Calculate weighted score (rebalance weights with calibration + adaptive thresholds)
    // Component scores are 0-100; normalize to 0-1 before calibration/weighting
    const calibratedText = PhishGuardHelpers.calibrateScore((textResult.score || 0) / 100, "TEXT");
    const calibratedURL = PhishGuardHelpers.calibrateScore((urlResult.score || 0) / 100, "URL");
    const calibratedSender = PhishGuardHelpers.calibrateScore((senderResult.score || 0) / 100, "SENDER");

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
    const category = this._detectCategory(emailData.body, textResult, urlResult, senderResult);

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
        textFlags: textResult.flags,
        urlFlags: urlResult.flags,
        senderFlags: senderResult.flags,
        urlCount: urlResult.urlCount,
        flaggedURLs: urlResult.flaggedURLs || []
      },
      confidence: textResult.confidence,
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
   * ─── Text Content Analysis (Improved) ───
   */
 async analyzeText(body, subject = "", senderDomain = "") {
    const result = { score: 0, flags: [], confidence: 0 };

    // === PRIVACY SHIELD: Scrub data before analysis ===
    const cleanBody = PhishGuardHelpers.anonymizeText(body);
    const cleanSubject = PhishGuardHelpers.anonymizeText(subject);

    PhishGuardHelpers.log("Analyzing anonymized content:", cleanSubject);

    // Combine subject + body, lowercase for keyword matching
    const fullText = `${cleanSubject} ${cleanBody}`.toLowerCase();
    if (!fullText.trim()) return result;
    // After fullText is prepared
    const nlpScore = await this._nlpPhishingScore(fullText);

    if (nlpScore > 0.6) { // threshold for phishing
      result.score += Math.round(nlpScore * 40); // add weighted points
      result.flags.push({
        code: "NLP_MODEL",
        message: `AI model flagged this as phishing with ${Math.round(nlpScore*100)}% confidence`
      });
    }

    // -------------------------------
    // 1. Urgency keywords
    // -------------------------------
    const urgencyMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.URGENCY_KEYWORDS);
    if (urgencyMatches.length > 0) {
      result.score += Math.min(urgencyMatches.length * 12, 30);
      result.flags.push({ code: "URGENCY", message: `Urgency tactics: "${urgencyMatches.join(", ")}"` });
    }

    // 2. Threat keywords
    const threatMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.THREAT_KEYWORDS);
    if (threatMatches.length > 0) {
      result.score += Math.min(threatMatches.length * 15, 30);
      result.flags.push({ code: "THREAT", message: `Threatening language: "${threatMatches.join(", ")}"` });
    }

    // 3. Financial bait
    const financialMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.FINANCIAL_KEYWORDS);
    if (financialMatches.length > 0) {
      result.score += Math.min(financialMatches.length * 10, 27);
      result.flags.push({ code: "FINANCIAL", message: `Financial bait: "${financialMatches.join(", ")}"` });
    }

    // 4. Impersonation patterns
    const impersonationMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.IMPERSONATION_KEYWORDS);
    if (impersonationMatches.length >= 2) {
      result.score += 15;
      result.flags.push({ code: "IMPERSONATION", message: "Generic impersonation language (e.g., 'Dear Customer')" });
    }

    // 5. Action requests
    const actionMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.ACTION_KEYWORDS);
    if (actionMatches.length > 0) {
      result.score += Math.min(actionMatches.length * 8, 25);
      result.flags.push({ code: "ACTION", message: `Pushes you to act: "${actionMatches.join(", ")}"` });
    }

    // 6. Regional scam patterns (Hinglish)
    const hinglishMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.HINGLISH_KEYWORDS);
    if (hinglishMatches.length > 0) {
      result.score += Math.min(hinglishMatches.length * 10, 20);
      result.flags.push({ code: "HINGLISH", message: `Regional scam pattern: "${hinglishMatches.join(", ")}"` });
    }

    // 7. Grammar errors
    const grammarMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.GRAMMAR_INDICATORS);
    if (grammarMatches.length > 0) {
      result.score += Math.min(grammarMatches.length * 8, 10);
      result.flags.push({ code: "GRAMMAR", message: "Contains grammar errors common in scam emails" });
    }

    // 8. Excessive capitalization
    const capsInfo = this._calculateCapsRatio(body);
    if (capsInfo.ratio > 0.3 && body.length > 50) {
      result.score += 10;
      result.flags.push({ code: "CAPS", message: "Excessive use of CAPITAL LETTERS (shouting tactic)" });
    }

    // 9. Excessive punctuation
    const exclamationCount = (body.match(/!{2,}/g) || []).length;
    const questionCount = (body.match(/\?{2,}/g) || []).length;
    if (exclamationCount + questionCount >= 3) {
      result.score += 8;
      result.flags.push({ code: "PUNCTUATION", message: "Excessive punctuation (!! or ??) — common in scams" });
    }

    // 10. Domain/Text mismatch (NEW)
    const brandMatches = this._findKeywordMatches(fullText, SCAM_CONSTANTS.BRAND_KEYWORDS);
    if (brandMatches.length > 0 && senderDomain) {
      const mismatch = brandMatches.some(brand => !senderDomain.includes(brand.toLowerCase()));
      if (mismatch) {
        result.score += 20;
        result.flags.push({ code: "DOMAIN_MISMATCH", message: `Mentions "${brandMatches.join(", ")}" but sender domain is ${senderDomain}` });
      }
    }

    // Cap score at 100
    result.score = Math.min(result.score, 100);

    // Confidence = ratio of triggered checks to total checks
    const totalChecks = 10;
    const triggeredChecks = result.flags.length;
    result.confidence = triggeredChecks / totalChecks;

    return result;
  },

  // ─── NLP Model Inference (safe stub) ───
  async _nlpPhishingScore(text) {
    try {
      if (!this.phishingModel) return 0;
      // Tokenizer not available here; skip model inference.
      PhishGuardHelpers.log('Phishing model loaded but tokenizer missing; skipping model inference');
      return 0;
    } catch (e) {
      return 0;
    }
  },

  // ==============================================
  // CATEGORY DETECTION (Improved & Robust)
  // ==============================================
  _detectCategory(text, textResult = { score: 0 }, urlResult = { flags: [], score: 0 }, senderResult = { flags: [], score: 0 }) {
    if (!text) return null;
    const lowerText = text.toLowerCase();

    let bestCategory = null;
    let bestMatchScore = 0;

    for (const [key, cat] of Object.entries(SCAM_CONSTANTS.SCAM_CATEGORIES)) {
      const matchScore = cat.keywords.reduce((sum, kw) => {
        const matched = PhishGuardHelpers.fuzzyMatch ? PhishGuardHelpers.fuzzyMatch(lowerText, kw) : lowerText.includes(kw);
        return matched ? sum + (cat.weights?.[kw] || 1) : sum;
      }, 0);

      if (
        matchScore > bestMatchScore ||
        (matchScore === bestMatchScore && (cat.severity || 0) > (bestCategory?.severity || 0))
      ) {
        bestMatchScore = matchScore;
        bestCategory = {
          ...cat,
          matchedKeywords: cat.keywords.filter(kw => PhishGuardHelpers.fuzzyMatch ? PhishGuardHelpers.fuzzyMatch(lowerText, kw) : lowerText.includes(kw)),
          matchScore
        };
      }
    }

    if (!bestCategory) return null;

    const threshold = bestCategory.minMatch || 2;
    const hasExtraSignals = (urlResult.flags && urlResult.flags.length > 0) || (senderResult.flags && senderResult.flags.length > 0);
    const effectiveThreshold = hasExtraSignals ? threshold - 1 : threshold;

    if (bestMatchScore >= effectiveThreshold || (bestMatchScore === 1 && textResult.score >= 50)) {
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
      ...(textResult.flags || []),
      ...(urlResult.flags || []),
      ...(senderResult.flags || [])
    ];

    if (allFlags.length === 0) {
      return {
        summary: "✅ SAFE: No scam indicators detected.",
        details: [],
        educationalTips: ["Always verify unexpected requests through official channels."],
        metadata: { textScore: textResult.score, urlScore: urlResult.score, senderScore: senderResult.score, categoryConfidence: category?.confidence || null }
      };
    }

    const totalScore = Math.round((textResult.score * 0.4) + (urlResult.score * 0.4) + (senderResult.score * 0.2));
    const hasStrongNonTextSignals = (urlResult.score || 0) > 20 || (senderResult.score || 0) > 15;
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

    const flagTips = [];
    if ((textResult.flags || []).some(f => f.code === "URGENCY")) flagTips.push("Scammers often pressure you with urgency. Pause and verify before acting.");
    if ((textResult.flags || []).some(f => f.code === "THREAT")) flagTips.push("Threatening language is a scare tactic. Legitimate organizations don’t threaten arrest or fines via email.");
    if ((urlResult.flags || []).some(f => f.code === "SUSPICIOUS_URL")) flagTips.push("Hover over links to check the real domain before clicking.");
    if ((senderResult.flags || []).some(f => f.code === "MISMATCH")) flagTips.push("Sender address doesn’t match display name — a common impersonation trick.");

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

    const categoryKey = category ? Object.entries(SCAM_CONSTANTS.SCAM_CATEGORIES).find(([k, v]) => v.label === category.label)?.[0] : null;

    return {
      summary,
      details: [
        ...allFlags.map(f => f.message || f),
        ...(category?.matchedKeywords ? [`Category keywords: ${category.matchedKeywords.join(', ')}`] : [])
      ],
      educationalTips: flagTips.length > 0 ? flagTips : categoryKey ? [educationalTipsMap[categoryKey]] : ["When in doubt, contact the organization directly using their official website or phone number."],
      metadata: { textScore: textResult.score, urlScore: urlResult.score, senderScore: senderResult.score, categoryConfidence: category?.confidence || null, severity: category?.severity || null }
    };
  },

  // PRIVATE HELPERS
  _findKeywordMatches(text, keywords) {
    if (!text) return [];
    const lowerText = text.toLowerCase();
    return (keywords || []).filter(keyword => PhishGuardHelpers.fuzzyMatch ? PhishGuardHelpers.fuzzyMatch(lowerText, keyword.toLowerCase()) : lowerText.includes(keyword.toLowerCase()));
  },

  _calculateCapsRatio(text) {
    if (!text || text.length < 5) return { ratio: 0, totalLetters: 0, totalCaps: 0 };
    const letters = text.replace(/[^a-zA-Z]/g, '');
    if (letters.length === 0) return { ratio: 0, totalLetters: 0, totalCaps: 0 };
    const caps = letters.replace(/[^A-Z]/g, '');
    const ratio = caps.length / letters.length;
    return { ratio, totalLetters: letters.length, totalCaps: caps.length };
  }
};

// Expose loader so callers can await model load: await PhishAIEngine.loadPhishingModel()
PhishAIEngine.loadPhishingModel = loadPhishingModel;

// Universal module definition for safe export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishAIEngine;
} else if (typeof window !== 'undefined') {
  window.PhishAIEngine = PhishAIEngine;
}

// Try to load model in Node but ignore errors
if (typeof window === 'undefined') {
  loadPhishingModel().catch(() => {});
}
/**
 * ============================================
 * CONSTANTS.JS — Scam Pattern Database
 * Role: Cyber-Analyst
 * Purpose: All scam patterns, keywords, and
 * detection rules live here
 * ============================================
 */

const SCAM_CONSTANTS = {

  // ── Risk Thresholds ──
  RISK_LEVELS: {
    SAFE: { min: 0, max: 29, label: "Safe", color: "#22c55e" },
    CAUTION: { min: 30, max: 69, label: "Caution", color: "#f59e0b" },
    DANGER: { min: 70, max: 100, label: "High Risk", color: "#ef4444" }
  },

  // ── Score Weights ──
  SCORE_WEIGHTS: {
    TEXT: 0.4,
    URL: 0.4,
    SENDER: 0.2
  },

  // ── Urgency Keywords (Score: High) ──
  URGENCY_KEYWORDS: [
    "act now", "act immediately", "urgent action required",
    "immediate attention", "expires today", "last chance",
    "limited time", "only hours left", "deadline",
    "suspend", "suspended", "will be closed",
    "within 24 hours", "within 48 hours",
    "account will be locked", "account compromised",
    "unauthorized access", "unusual activity",
    "verify immediately", "confirm your identity",
    "failure to respond", "legal action"
  ],

  // ── Threat Keywords (Score: High) ──
  THREAT_KEYWORDS: [
    "legal action", "police report", "court order",
    "arrest warrant", "criminal charges", "lawsuit",
    "penalty", "fine", "prosecution",
    "account terminated", "permanently banned",
    "report to authorities", "federal investigation"
  ],

  // ── Financial Bait Keywords (Score: Medium-High) ──
  FINANCIAL_KEYWORDS: [
    "congratulations you've won", "you are selected",
    "claim your prize", "lottery winner",
    "million dollars", "inheritance",
    "beneficiary", "unclaimed funds",
    "wire transfer", "western union", "moneygram",
    "bitcoin payment", "cryptocurrency",
    "investment opportunity", "guaranteed returns",
    "double your money", "risk free",
    "credit card required", "ssn", "social security",
    "bank account details", "routing number",
    "pin number", "cvv"
  ],

  // ── Impersonation Keywords (Score: Medium) ──
  IMPERSONATION_KEYWORDS: [
    "dear customer", "dear user", "dear member",
    "valued customer", "account holder",
    "we have detected", "we noticed",
    "your account has been", "as per our records",
    "security department", "fraud department",
    "technical support", "helpdesk",
    "official notice", "important notification"
  ],

  // ── Action Request Keywords (Score: Medium) ──
  ACTION_KEYWORDS: [
    "click here", "click below", "click the link",
    "log in here", "sign in", "verify your account",
    "update your information", "confirm your details",
    "download attachment", "open attached",
    "fill out the form", "submit your",
    "reply with your", "send your details",
    "call this number", "contact us immediately"
  ],

  // ── Hinglish/Indian Scam Patterns ──
  HINGLISH_KEYWORDS: [
    "aapka account", "aapka khata",
    "block ho jayega", "band ho jayega",
    "kyc update", "kyc verification",
    "aadhar card", "aadhaar",
    "pan card link", "pan card update",
    "upi id", "paytm kyc",
    "phonepe", "google pay",
    "sbi bank", "rbi notice",
    "income tax notice", "gst notice",
    "custom duty", "parcel roka gaya",
    "lottery jeet", "prize jeeta",
    "crore rupees", "lakh rupees"
  ],

  // ── Scam Categories ──
  SCAM_CATEGORIES: {
    BANKING: {
      label: "Banking/Financial Scam",
      icon: "🏦",
      keywords: ["bank", "account", "credit", "debit", "transaction", "payment", "transfer"]
    },
    DELIVERY: {
      label: "Package/Delivery Scam",
      icon: "📦",
      keywords: ["package", "delivery", "shipment", "tracking", "fedex", "ups", "amazon", "order"]
    },
    JOB: {
      label: "Job/Employment Scam",
      icon: "💼",
      keywords: ["job offer", "work from home", "earn money", "hiring", "salary", "income", "opportunity"]
    },
    GOVERNMENT: {
      label: "Government Impersonation",
      icon: "🏛️",
      keywords: ["irs", "tax", "government", "court", "legal", "police", "federal", "social security"]
    },
    LOTTERY: {
      label: "Lottery/Prize Scam",
      icon: "🎰",
      keywords: ["winner", "prize", "lottery", "congratulations", "selected", "lucky", "claim"]
    },
    ROMANCE: {
      label: "Romance/Dating Scam",
      icon: "💕",
      keywords: ["lonely", "love", "relationship", "dating", "beautiful", "handsome", "meet me"]
    },
    TECH_SUPPORT: {
      label: "Tech Support Scam",
      icon: "🖥️",
      keywords: ["virus detected", "computer infected", "tech support", "microsoft", "apple support", "security alert"]
    },
    CRYPTO: {
      label: "Cryptocurrency Scam",
      icon: "🪙",
      keywords: ["bitcoin", "ethereum", "crypto", "blockchain", "nft", "token", "wallet", "mining"]
    }
  },

  // ── Suspicious TLDs ──
  SUSPICIOUS_TLDS: [
    ".xyz", ".top", ".club", ".online", ".site",
    ".icu", ".buzz", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".win", ".loan", ".click",
    ".link", ".work", ".date", ".racing",
    ".download", ".stream", ".bid"
  ],

  // ── Trusted Domains (Whitelist) ──
  TRUSTED_DOMAINS: [
    "google.com", "gmail.com", "microsoft.com",
    "outlook.com", "apple.com", "amazon.com",
    "paypal.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "usps.com", "fedex.com",
    "ups.com", "irs.gov", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "rbi.org.in",
    "gov.in", "india.gov.in"
  ],

  // ── URL Red Flags ──
  URL_RED_FLAGS: {
    IP_ADDRESS: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    EXCESSIVE_SUBDOMAINS: /([^.]+\.){4,}/,
    SUSPICIOUS_PATHS: /\/(secure|login|verify|update|confirm|account|banking|signin)/i,
    DATA_URI: /^data:/i,
    JAVASCRIPT_URI: /^javascript:/i,
    ENCODED_CHARS: /%[0-9a-f]{2}/i,
    AT_SYMBOL: /@/,
    DOUBLE_SLASH_IN_PATH: /https?:\/\/[^/]+\/\/.+/
  },

  // ── Common Typosquatting Patterns ──
  TYPOSQUAT_MAP: {
    "google": ["g00gle", "gogle", "googl", "gooogle", "googIe"],
    "amazon": ["amaz0n", "amazn", "amazom", "arnazon", "amazón"],
    "paypal": ["paypa1", "paypai", "paypaI", "peypal", "paypa"],
    "apple":  ["app1e", "appie", "appIe", "aple", "appl"],
    "microsoft": ["micr0soft", "mircosoft", "microsft", "microsoft"],
    "facebook": ["faceb00k", "facebok", "facbook"],
    "netflix": ["netf1ix", "netfIix", "netflix"],
    "sbi":    ["sb1", "sbì"],
    "hdfc":   ["hdf c", "hdtc"]
  },

  // ── Suspicious File Extensions ──
  SUSPICIOUS_EXTENSIONS: [
    ".exe", ".bat", ".cmd", ".scr", ".pif",
    ".js", ".vbs", ".wsf", ".msi", ".jar",
    ".ps1", ".reg", ".html", ".htm", ".hta"
  ],

  // ── Grammar Error Indicators ──
  GRAMMAR_INDICATORS: [
    "kindly do the needful", "revert back",
    "please to", "we was", "you has been",
    "your been selected", "informations",
    "dears", "sir/madam", "respected sir",
    "aborting your", "aborting the transaction"
  ]
};

// Make available across scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SCAM_CONSTANTS;
}
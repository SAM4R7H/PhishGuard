/**
 * ============================================
 * TEST-EMAILS.JS — Test Cases for Development
 * Purpose: Sample emails to test detection
 * Usage: Paste these into browser console to test
 * ============================================
 */

const TEST_EMAILS = {

  // ── Should be flagged HIGH RISK ──
  bankingScam: {
    body: `Dear Valued Customer,

We have detected unusual activity on your Bank of America account. 
Your account will be SUSPENDED within 24 hours unless you verify your identity immediately.

Click here to verify: http://bankofamerica-secure.xyz/login

Please provide your account number, SSN, and PIN to restore access.

Failure to respond will result in permanent account closure and legal action.

Regards,
Bank of America Security Department`,
    sender: "security@bankamerica-alert.xyz",
    displayName: "Bank of America",
    subject: "URGENT: Account Suspension Notice",
    expectedScore: "70+",
    expectedCategory: "Banking/Financial Scam"
  },

  // ── Should be flagged CAUTION ──
  deliveryScam: {
    body: `Hello,

Your package #US9738281 could not be delivered. 
Please update your delivery address to receive your item.

Track your package: https://fedex-tracking.top/update

Thank you,
FedEx Delivery Team`,
    sender: "delivery@fedex-notifications.club",
    displayName: "FedEx",
    subject: "Delivery Failed - Action Required",
    expectedScore: "40-70",
    expectedCategory: "Package/Delivery Scam"
  },

  // ── Should be flagged SAFE ──
  legitimateEmail: {
    body: `Hi Team,

Just a reminder that our weekly standup is tomorrow at 10 AM. 
Please prepare your updates.

Thanks,
Sarah`,
    sender: "sarah.johnson@company.com",
    displayName: "Sarah Johnson",
    subject: "Weekly Standup Reminder",
    expectedScore: "<30",
    expectedCategory: "None"
  },

  // ── Hinglish Scam ──
  hinglishScam: {
    body: `Dear Customer,

Aapka SBI account block ho jayega agar aap apna KYC update nahi karte 24 ghante mein.

Abhi click karein: http://sbi-kyc-update.online/verify

Apna Aadhaar card number aur PAN card details send karein.

Dhanyavaad,
SBI Bank Team`,
    sender: "support@sbi-bank-india.xyz",
    displayName: "SBI Bank",
    subject: "KYC Update Required - Account Block Warning",
    expectedScore: "70+",
    expectedCategory: "Banking/Financial Scam"
  },

  // ── Lottery Scam ──
  lotteryScam: {
    body: `CONGRATULATIONS!!! YOU HAVE WON!!!

You have been selected as the lucky winner of the Microsoft International Lottery.
You have won $5,000,000 (Five Million Dollars)!!!

To claim your prize, send your full name, address, phone number, 
and bank account details to: claims@lottery-winner-intl.tk

You must respond within 48 hours or your prize will be forfeited.

Sir/Madam, kindly do the needful and revert back.

Dr. James Williams
Claims Department`,
    sender: "winner@microsoft-lottery.ga",
    displayName: "Microsoft Lottery",
    subject: "YOU WON $5,000,000!!!",
    expectedScore: "85+",
    expectedCategory: "Lottery/Prize Scam"
  }
};

// Quick test function — run in console
function runTests() {
  console.log("=== PhishGuard Test Suite ===\n");

  for (const [name, testCase] of Object.entries(TEST_EMAILS)) {
    const result = PhishAIEngine.analyze({
      body: testCase.body,
      sender: testCase.sender,
      displayName: testCase.displayName,
      subject: testCase.subject,
      urls: PhishGuardHelpers.extractURLs(testCase.body)
    });

    console.log(`📧 ${name}`);
    console.log(`   Score: ${result.score}/100 (Expected: ${testCase.expectedScore})`);
    console.log(`   Category: ${result.category} (Expected: ${testCase.expectedCategory})`);
    console.log(`   Flags: ${result.explanation.details.length}`);
    console.log(`   Time: ${result.processingTime}ms`);
    console.log('');
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TEST_EMAILS, runTests };
}
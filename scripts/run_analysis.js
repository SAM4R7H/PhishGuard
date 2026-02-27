const path = require('path');

// Provide global dependencies expected by ai-engine
const _helpers = require(path.join(__dirname, '..', 'utils', 'helpers'));
// Provide minimal fallbacks for helper methods used by the engine
_helpers.calibrateScore = _helpers.calibrateScore || (score => score);
_helpers.getAdaptiveWeights = _helpers.getAdaptiveWeights || (tenantId => null);
_helpers.fuzzyMatch = _helpers.fuzzyMatch || ((text, kw) => (text || '').includes(kw));
global.PhishGuardHelpers = _helpers;
global.SCAM_CONSTANTS = require(path.join(__dirname, '..', 'utils', 'constants'));
global.PhishScanner = require(path.join(__dirname, 'scanner'));

const PhishAIEngine = require('./ai-engine');

(async () => {
  try {
    if (PhishAIEngine.loadPhishingModel) {
      console.log('[Runner] Loading phishing model...');
      await PhishAIEngine.loadPhishingModel();
      console.log('[Runner] Model loaded');
    } else {
      console.log('[Runner] No explicit loader; waiting for model to appear...');
      while (!PhishAIEngine.phishingModel) await new Promise(r => setTimeout(r, 200));
    }

    const sampleEmail = {
      body: "Urgent: Your account will be suspended. Click here to verify.",
      subject: "Account Suspension Notice",
      sender: "notice@bank-example.com",
      displayName: "Bank Support",
      urls: ["http://malicious.example/verify"],
      tenantId: "default"
    };

    const result = await PhishAIEngine.analyze(sampleEmail);
    console.log('[Runner] Scan result:');
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error('[Runner] Error running analysis:', err);
    process.exitCode = 1;
  }
})();
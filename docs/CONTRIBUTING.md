# 🛠️ Contributing to PhishGuard

Welcome to the PhishGuard development team! 

To keep our codebase stable, secure, and bug-free, we follow a strict **Feature Branch Workflow**. Please read this guide carefully before writing any code.

---

## 🌳 1. The Branching Strategy

We never push code directly to the `main` branch. We use a 3-tier system:

1. **`main`**: The Production version. (Locked 🔒 - Only the Integration Lead can merge here).
2. **`test-integration`**: The Staging area. This is where we combine everyone's code to test it together. **(All Pull Requests must target this branch!)**
3. **`feat-[role]`**: Your personal workspace.

### Find Your Assigned Branch:
* **Cyber-Analyst:** `feat-url-scanner` *(Edits `scanner.js` & `constants.js`)*
* **Intelligence Lead:** `feat-ai-logic` *(Edits `ai-engine.js`)*
* **Extension Architect:** `feat-ui-architect` *(Edits `content.js` & `popup/`)*
* **Integration Lead:** `feat-integration` *(Edits `background.js` & `manifest.json`)*

---

## 💻 2. The Daily Developer Workflow

Follow this 5-step loop every time you work on the project.

### Step 1: Sync Your Local Machine
Before you start coding, make sure you have the latest updates from the team.
```bash
git checkout test-integration
git pull origin test-integration

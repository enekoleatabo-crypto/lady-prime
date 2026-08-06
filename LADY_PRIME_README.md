# 🔒 LADY PRIME - DeFi Security & Rugpull Detection Engine v2.0

## Overview

**LADY PRIME** is a comprehensive **security analysis and rugpull detection system** for DeFi liquid staking protocols. It analyzes protocol smart contracts to identify:

- 🚨 **Centralized admin control** - Single owner with no timelock/multisig
- 💰 **Fee siphoning mechanisms** - Uncapped fees draining user funds
- 🔐 **Withdrawal traps** - Locks and restrictions that trap user funds
- 🌉 **Bridge vulnerabilities** - Cross-chain attack vectors
- 💸 **Reward clawbacks** - Protocols taking back earned rewards
- 🏛️ **Governance manipulation** - Centralized control of critical functions

Built for **DeFi security engineers** to catch scammers, rugpulls, and malicious protocols before users lose money.

---

## 🎯 What This Tool Does

### **Phase 1: Protocol Discovery**
- Fetches 974+ protocols from DefiLlama-Adapters repository
- Filters for liquid staking protocols
- Extracts all contract addresses automatically
- Saves raw data to `liquid_staking_analysis.json`

### **Phase 2: Security Analysis**
- **Analyzes 6 critical contract types:**
  1. Reward Distribution Contracts
  2. Treasury/Multisig Contracts
  3. Fee Collection Contracts
  4. Staking Pool Contracts
  5. Bridge Contracts
  6. Governance Contracts

- **Detects function signatures:** withdraw, transfer, approve, claimRewards, emergencyWithdraw, etc.
- **Identifies red flags:** Centralized control, uncapped fees, withdrawal locks, bridge exploits
- **Calculates risk scores:** 0-100 scale (higher = more risky)
- **Assigns risk levels:** CRITICAL | HIGH | MEDIUM | LOW | MINIMAL

### **Phase 3: Rugpull Detection**
- Hidden admin functions enabling rugpull
- Exit scam indicators (no withdrawal mechanism, paused exits)
- Honeypot patterns (transfer restrictions, blacklists)
- Fee manipulation scams (uncapped fees, hidden recipients)
- Governance attack vectors (no voting delays, low quorum)

### **Phase 4: Report Generation**
Exports comprehensive reports in multiple formats:
- 📊 JSON - Full detailed analysis
- 📈 CSV - Spreadsheet format for sorting/filtering
- 📋 Risk Rankings - Protocols ranked by rugpull risk
- 📁 Individual Protocol Reports - Per-protocol deep dives

---

## 📋 Prerequisites

- Python 3.7+
- GitHub Personal Access Token (PAT)
- Internet connection

---

## ⚙️ Setup Instructions

### **1. Clone or Navigate to Repository**
```bash
cd lady-prime
```

### **2. Create Virtual Environment**
```bash
python -m venv venv
```

### **3. Activate Virtual Environment**

**Linux/Mac:**
```bash
source venv/bin/activate
```

**Windows:**
```bash
venv\Scripts\activate
```

### **4. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **5. Generate GitHub PAT**
1. Go to: https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Set these scopes:
   - ✅ `repo:status`
   - ✅ `public_repo`
   - ✅ `read:repo_hook`
4. Copy the token

### **6. Add GitHub PAT to .env**
Create or edit `.env` file in the repository root:
```env
GITHUB_PAT=your_github_pat_token_here
```

---

## 🚀 Running the Tool

### **Start the Full Analysis Pipeline**
```bash
python main.py
```

This will:
1. ✅ Discover liquid staking protocols from DefiLlama
2. ✅ Extract all contract addresses
3. ✅ Perform comprehensive security analysis
4. ✅ Generate rugpull risk reports
5. ✅ Export results in multiple formats

### **Expected Runtime**
- ~2-5 minutes for protocol discovery
- ~3-10 minutes for security analysis (depends on number of protocols)
- Total: ~5-15 minutes for complete analysis

---

## 📁 Generated Output Files

### **After running `python main.py`, you'll get:**

```
lady-prime/
├── liquid_staking_analysis.json          # Raw protocol data from DefiLlama
├── security_analysis_report.json         # Full security analysis for all protocols
├── security_analysis_report.csv          # Spreadsheet format (open in Excel/Sheets)
├── risk_rankings.json                    # Protocols ranked by risk score
└── protocol_reports/                     # Individual detailed reports
    ├── lido_security_report.json
    ├── rocket-pool_security_report.json
    ├── aave_security_report.json
    └── [more protocol reports...]
```

---

## 📊 Understanding the Reports

### **security_analysis_report.csv**
Open in Excel or Google Sheets. Columns include:
- **Protocol** - Protocol name
- **Risk Level** - CRITICAL | HIGH | MEDIUM | LOW | MINIMAL
- **Rugpull Score** - 0-100 (higher = more risky)
- **Investment Score** - 0-100 (higher = less trustworthy)
- **Reward Contracts** - Count of detected reward contracts
- **Treasury Contracts** - Count of treasury/multisig contracts
- **Fee Contracts** - Count of fee collection contracts
- **Staking Contracts** - Count of staking pool contracts
- **Bridge Contracts** - Count of bridge contracts
- **Centralized Control** - Yes/No
- **Withdrawal Restrictions** - Yes/No
- **Recommendation** - Investment recommendation

### **risk_rankings.json**
Quick reference for protocols ranked by risk:
```json
{
  "rank": 1,
  "protocol": "protocol-name",
  "risk_level": "CRITICAL",
  "rugpull_score": 89.5,
  "recommendation": "DO NOT INVEST - Extreme rugpull risk detected..."
}
```

### **Individual Protocol Reports** (protocol_reports/)
Deep dive analysis for each protocol:
```json
{
  "protocol": "lido",
  "security_analysis": {
    "reward_distribution": {
      "addresses": ["0x...", "0x..."],
      "functions_found": ["distributeRewards", "claimRewards"],
      "red_flags": ["Centralized reward distribution..."],
      "risk_score": 15.0
    },
    "treasury_multisig": {
      "addresses": ["0x..."],
      "functions_found": ["withdraw", "transfer"],
      "centralized": true,
      "red_flags": ["Single admin can drain treasury..."],
      "risk_score": 25.0
    },
    ...
  },
  "rugpull_assessment": {
    "rugpull_score": 35.0,
    "risk_level": "MEDIUM",
    "recommendation": "REVIEW - Significant risks identified..."
  }
}
```

---

## 🚨 Red Flags Detected

### **Critical Red Flags (Extreme Risk)**
- ⛔ Single admin can drain treasury without timelock
- ⛔ Rewards can be clawed back from users
- ⛔ Withdrawal functions permanently locked/paused
- ⛔ No emergency withdrawal mechanism
- ⛔ Bridge has no rate limiting

### **High Risk Red Flags**
- ⚠️ No multi-signature requirement on critical functions
- ⚠️ Admin-only fee withdrawal (>10% fees)
- ⚠️ Withdrawal delays >30 days
- ⚠️ Governance can be changed immediately (no timelock)
- ⚠️ Bridge fees >5%

### **Medium Risk Red Flags**
- 📋 Fees concentrated to single recipient
- 📋 Governance parameters can be modified by owner
- 📋 Missing documentation or methodology
- 📋 Ownership concentration patterns

---

## 📈 Risk Score Breakdown

Each protocol receives an **Investment Score (0-100)**:

| Score | Risk Level | Recommendation |
|-------|-----------|-----------------|
| 80-100 | 🚨 CRITICAL | DO NOT INVEST |
| 65-79 | ⛔ HIGH | AVOID |
| 50-64 | ⚠️ MEDIUM | CAUTION - Thorough review needed |
| 30-49 | 📋 MODERATE | Acceptable with due diligence |
| 15-29 | ✅ LOW | Minimal risk detected |
| 0-14 | ✅ MINIMAL | No major red flags |

---

## 🔍 How to Analyze Results

### **Step 1: Check Risk Rankings**
```bash
cat risk_rankings.json | grep -A 5 "CRITICAL"
```
Identifies CRITICAL risk protocols to avoid immediately.

### **Step 2: Review Top Protocols**
Open `security_analysis_report.csv` in Excel and:
- Sort by "Risk Level" (descending)
- Sort by "Rugpull Score" (descending)
- Focus on CRITICAL and HIGH risk protocols

### **Step 3: Deep Dive Analysis**
For protocols of interest:
```bash
cat protocol_reports/protocol-name_security_report.json | python -m json.tool
```

Review:
- **Red flags** - What vulnerabilities were detected?
- **Contract addresses** - Verify against official docs
- **Functions found** - What can admins do?
- **Risk scores** - Which categories are most problematic?

### **Step 4: Manual Verification**
For protocols you want to invest in:
1. Copy contract addresses from report
2. Visit Etherscan/Polygonscan/etc
3. Verify ownership and functions
4. Check transaction history
5. Review official documentation

---

## ⚙️ Advanced Usage

### **Analyze Existing Data (Skip Discovery)**
If you already have `liquid_staking_analysis.json`:
```python
from security_orchestrator import SecurityOrchestrator

orchestrator = SecurityOrchestrator("liquid_staking_analysis.json")
orchestrator.run_full_analysis()
```

### **Custom Report Filtering**
```python
from security_orchestrator import SecurityOrchestrator

orchestrator = SecurityOrchestrator("liquid_staking_analysis.json")
orchestrator.load_protocol_data()
orchestrator.analyze_all_protocols()

# Get only CRITICAL protocols
critical = orchestrator.filter_critical_protocols()
for protocol in critical:
    print(f"CRITICAL: {protocol['protocol']} - Score: {protocol['rugpull_score']}")
```

### **Export Custom Format**
```python
# Export only to CSV
orchestrator.export_to_csv("my_custom_report.csv")

# Export risk rankings only
orchestrator.export_risk_rankings("my_rankings.json")
```

---

## 🐛 Troubleshooting

### ❌ "401 Authentication Error"
**Problem:** GitHub PAT is invalid
```
401 Error: Authentication failed
```
**Solution:**
- Check `.env` file has correct `GITHUB_PAT`
- Regenerate token at https://github.com/settings/tokens
- Ensure token has required scopes

### ❌ "ModuleNotFoundError"
**Problem:** Missing dependencies
```
ModuleNotFoundError: No module named 'requests'
```
**Solution:**
```bash
pip install -r requirements.txt
```

### ❌ "Rate Limit Reached"
**Problem:** GitHub API rate limit exceeded
```
WARNING: Only 50 API requests remaining!
```
**Solution:**
- Wait 1 hour for rate limit reset
- Use authenticated requests (you already are with PAT)
- Maximum 5,000 requests/hour with PAT

### ❌ "File Not Found"
**Problem:** `liquid_staking_analysis.json` missing
```
FileNotFoundError: liquid_staking_analysis.json not found
```
**Solution:**
- Run protocol discovery first: `python main.py`
- Or ensure file exists in same directory

---

## 📊 Contract Analysis Details

### **Reward Distribution Contracts**
Analyzes:
- `rewardDistributor`, `incentiveDistributor`, `rewardManager`
- Functions: `distributeRewards()`, `claimRewards()`, `getReward()`
- Red flags: Centralized distribution, clawback capability

### **Treasury/Multisig Contracts**
Analyzes:
- `treasury`, `multisig`, `admin`, `owner`
- Functions: `withdraw()`, `transfer()`, `emergencyWithdraw()`
- Red flags: Single admin, no timelock, unilateral drain capability

### **Fee Collection Contracts**
Analyzes:
- `feeCollector`, `feeDistributor`, `protocolFee`
- Functions: `collectFees()`, `withdrawFees()`, `setFeePercentage()`
- Red flags: Uncapped fees, no recipient verification

### **Staking Pool Contracts**
Analyzes:
- `stakingPool`, `vault`, `depositPool`
- Functions: `withdraw()`, `unstake()`, `redeem()`
- Red flags: Withdrawal locks, pause capability, delays >30 days

### **Bridge Contracts**
Analyzes:
- `bridge`, `tokenBridge`, `bridgeVault`
- Functions: `transferOut()`, `claim()`, `releaseFunds()`
- Red flags: No rate limiting, unilateral control

### **Governance Contracts**
Analyzes:
- Access control: `onlyOwner`, `onlyAdmin`, `hasRole()`
- Patterns: `timelock`, `multisig`, voting delays
- Red flags: Centralized ownership, no timelock, no multisig

---

## 🔐 Security Notes

- ✅ **Read-only analysis** - No contract interaction or fund movements
- ✅ **Transparent data source** - All from public DefiLlama-Adapters
- ✅ **No external APIs** - Uses GitHub API only
- ✅ **Local processing** - All analysis happens on your machine
- ✅ **Reproducible** - Same data every run

---

## 📞 Support

For issues:
1. Check troubleshooting section above
2. Verify GitHub PAT is valid
3. Ensure `.env` file is in repository root
4. Check internet connection
5. Verify Python version ≥ 3.7

---

## 📝 Version History

- **v2.0** - Complete rewrite with security analysis + rugpull detection
- **v1.0** - Initial protocol discovery version

---

## ⚠️ Disclaimer

This tool provides **pattern analysis** based on smart contract code. It is:
- ✅ Useful for identifying suspicious governance patterns
- ✅ Helpful for spotting known rugpull indicators
- ❌ NOT a guarantee of protocol safety
- ❌ NOT a substitute for professional audit
- ❌ NOT financial advice

**Always:**
1. Review official documentation
2. Verify contract addresses on-chain
3. Conduct thorough due diligence
4. Consult security professionals
5. Never invest more than you can afford to lose

---

## 🎯 Use Case: DeFi Security Engineer

This tool is designed for security researchers and engineers to:
- 🔍 Identify suspicious governance patterns
- 🚨 Detect known rugpull mechanisms
- ⚖️ Compare protocol security postures
- 📊 Generate comparative risk reports
- 🛡️ Protect users from malicious protocols

---

**Built for catching thieves, scammers & rugpull admins with suspicious contracts! 🔒**

**Ready to scan? Run: `python main.py`**

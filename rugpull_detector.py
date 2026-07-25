import json
from typing import Dict, List, Any
from datetime import datetime

class RugpullDetector:
    """
    Specialized rugpull detection engine that identifies scammer patterns,
    suspicious contract behavior, and investment traps in DeFi protocols.
    """
    
    def __init__(self):
        # Known rugpull patterns from historical analysis
        self.rugpull_indicators = {
            "ownership_trap": {
                "description": "Single owner with no timelock or multisig",
                "severity": 9,
                "keywords": ["onlyOwner", "emergencyWithdraw", "ownerWithdraw"]
            },
            "hidden_mint_function": {
                "description": "Protocol can mint unlimited tokens",
                "severity": 10,
                "keywords": ["mint(", "minter", "totalSupply++"]
            },
            "fee_siphoning": {
                "description": "High or uncapped fees that drain user funds",
                "severity": 8,
                "keywords": ["collectFees", "withdrawFees", ">10%"]
            },
            "fund_trap": {
                "description": "Users cannot withdraw funds due to locks or pauses",
                "severity": 9,
                "keywords": ["withdrawalLock", "pause", "emergencyWithdraw"]
            },
            "bridge_exploit": {
                "description": "Bridge contracts without rate limiting",
                "severity": 8,
                "keywords": ["transferOut", "noRateLimit", "bridgeFee"]
            },
            "centralized_treasury": {
                "description": "Treasury can be drained by single admin",
                "severity": 9,
                "keywords": ["treasury", "emergencyWithdraw", "onlyOwner"]
            },
            "reward_clawback": {
                "description": "Protocol can take back earned rewards",
                "severity": 8,
                "keywords": ["clawback", "slash", "penalize"]
            },
            "governance_hijack": {
                "description": "No governance protection on critical functions",
                "severity": 9,
                "keywords": ["onlyOwner", "onlyAdmin", "noGovernance"]
            },
            "timelocked_exit": {
                "description": "Exit functions have excessive delays",
                "severity": 7,
                "keywords": ["withdrawalDelay", "lockTime", ">30days"]
            },
            "supply_manipulation": {
                "description": "Protocol can manipulate token supply",
                "severity": 9,
                "keywords": ["burn(", "mint(", "burn", "totalSupply"]
            }
        }
    
    def check_hidden_admin_function(self, code: str, protocol_name: str) -> Dict[str, Any]:
        """Detect hidden admin functions that enable rugpull"""
        result = {
            "protocol": protocol_name,
            "has_hidden_admin": False,
            "admin_functions": [],
            "risk_level": "SAFE",
            "details": []
        }
        
        # Check for hidden transfer functions
        if "internalTransfer" in code or "safeTransfer" in code:
            if "onlyOwner" in code or "onlyAdmin" in code:
                result["admin_functions"].append("internalTransfer/safeTransfer (internal fund movement)")
                result["has_hidden_admin"] = True
        
        # Check for unrestricted burn
        if "burn(" in code and "require(msg.sender ==" not in code:
            result["admin_functions"].append("unrestricted burn (can destroy user tokens)")
            result["has_hidden_admin"] = True
        
        # Check for approval hijacking
        if "approve(" in code and "allowance" in code:
            if "onlyOwner" in code or "unlimited" in code.lower():
                result["admin_functions"].append("allowance manipulation (approval hijack risk)")
                result["has_hidden_admin"] = True
        
        # Check for delegate/voting manipulation
        if "delegate" in code and ("onlyOwner" in code or "onlyAdmin" in code):
            result["admin_functions"].append("voting delegation control (governance hijack)")
            result["has_hidden_admin"] = True
        
        if result["has_hidden_admin"]:
            result["risk_level"] = "CRITICAL"
            result["details"] = [
                "⚠️ Hidden admin functions detected that could enable rugpull",
                "Owner/Admin can execute functions that normal users cannot",
                "These functions pose extreme risk to protocol users"
            ]
        
        return result
    
    def check_exit_scam_indicators(self, code: str, protocol_name: str) -> Dict[str, Any]:
        """Detect classic exit scam patterns"""
        result = {
            "protocol": protocol_name,
            "exit_scam_risk": False,
            "risk_indicators": [],
            "risk_score": 0
        }
        
        risk_score = 0
        
        # Indicator 1: Can disable withdrawals
        if "pause" in code and "withdraw" in code:
            result["risk_indicators"].append({
                "indicator": "Withdrawal pause capability",
                "description": "Protocol can pause withdrawals, trapping user funds",
                "severity": 9
            })
            risk_score += 9
        
        # Indicator 2: No emergency withdraw visible
        if "withdraw" not in code and "redeem" not in code:
            result["risk_indicators"].append({
                "indicator": "No withdrawal mechanism",
                "description": "Protocol has no obvious way for users to exit",
                "severity": 10
            })
            risk_score += 10
        
        # Indicator 3: Time-locked exits
        if "withdrawalDelay" in code or "lockTime" in code:
            if "require" in code and "delay" in code.lower():
                result["risk_indicators"].append({
                    "indicator": "Excessive withdrawal delay",
                    "description": "Users cannot quickly exit their positions",
                    "severity": 7
                })
                risk_score += 7
        
        # Indicator 4: Admin can cancel withdrawals
        if "cancelWithdraw" in code and ("onlyOwner" in code or "onlyAdmin" in code):
            result["risk_indicators"].append({
                "indicator": "Cancellable withdrawals",
                "description": "Admin can cancel pending user withdrawals",
                "severity": 9
            })
            risk_score += 9
        
        # Indicator 5: Insufficient liquidity checks
        if "withdraw" in code:
            if "require(balance >=" not in code and "require(liquidity" not in code:
                result["risk_indicators"].append({
                    "indicator": "No liquidity verification",
                    "description": "Contract may not have funds to pay withdrawals",
                    "severity": 8
                })
                risk_score += 8
        
        result["risk_score"] = min(risk_score, 100)
        result["exit_scam_risk"] = risk_score >= 20
        
        return result
    
    def check_honeypot_indicators(self, code: str, protocol_name: str) -> Dict[str, Any]:
        """Detect honeypot scam patterns where users can't sell/withdraw"""
        result = {
            "protocol": protocol_name,
            "honeypot_risk": False,
            "honeypot_patterns": [],
            "risk_score": 0
        }
        
        risk_score = 0
        
        # Pattern 1: Transfer restrictions
        if "transfer" in code:
            if "require(false)" in code or "revert" in code:
                result["honeypot_patterns"].append({
                    "pattern": "Transfer restriction",
                    "description": "Transfers may be blocked for certain addresses",
                    "severity": 10
                })
                risk_score += 10
        
        # Pattern 2: Blacklist mechanism
        if "blacklist" in code or "isBlacklisted" in code:
            result["honeypot_patterns"].append({
                "pattern": "Blacklist mechanism",
                "description": "Protocol can blacklist addresses and prevent transfers",
                "severity": 9
            })
            risk_score += 9
        
        # Pattern 3: Transfer fee mechanism
        if "transferFee" in code or "tax" in code.lower():
            if "require" in code and "transferFee" in code:
                result["honeypot_patterns"].append({
                    "pattern": "Dynamic transfer tax",
                    "description": "Transfer taxes can be increased to 100%",
                    "severity": 8
                })
                risk_score += 8
        
        # Pattern 4: Approval restrictions
        if "approve" in code and "require(false)" in code:
            result["honeypot_patterns"].append({
                "pattern": "Blocked approvals",
                "description": "Users cannot approve token transfers",
                "severity": 9
            })
            risk_score += 9
        
        # Pattern 5: Swap restrictions
        if "swap" in code and ("onlyOwner" in code or "paused" in code):
            result["honeypot_patterns"].append({
                "pattern": "Restricted swaps",
                "description": "Only owner can swap or swaps are paused",
                "severity": 10
            })
            risk_score += 10
        
        result["risk_score"] = min(risk_score, 100)
        result["honeypot_risk"] = risk_score >= 15
        
        return result
    
    def check_fee_manipulation_scam(self, code: str, protocol_name: str) -> Dict[str, Any]:
        """Detect fee manipulation that drains protocol"""
        result = {
            "protocol": protocol_name,
            "fee_scam_risk": False,
            "fee_issues": [],
            "estimated_loss": "UNKNOWN"
        }
        
        issues_found = 0
        
        # Check 1: Uncapped fees
        if "fee" in code.lower():
            if "require" not in code or "max" not in code.lower():
                result["fee_issues"].append({
                    "issue": "Uncapped fee percentage",
                    "description": "Protocol can increase fees to any amount",
                    "risk": "Unlimited fund siphoning"
                })
                issues_found += 1
        
        # Check 2: Hidden fee recipient
        if "feeRecipient" in code or "feeCollector" in code:
            if "0x" in code:  # Hardcoded address
                result["fee_issues"].append({
                    "issue": "Hidden fee recipient",
                    "description": "Fees go to hardcoded address (likely attacker)",
                    "risk": "Ongoing fund theft"
                })
                issues_found += 1
        
        # Check 3: Emergency fee withdrawal
        if "emergencyFeeWithdraw" in code or "claimFees" in code:
            if "onlyOwner" in code or "onlyAdmin" in code:
                result["fee_issues"].append({
                    "issue": "Admin-only fee withdrawal",
                    "description": "Only owner can withdraw accumulated fees",
                    "risk": "Single point failure for all fees"
                })
                issues_found += 1
        
        # Check 4: Fee redistribution manipulation
        if "distributeFees" in code:
            if not ("mapping" in code or "array" in code):
                result["fee_issues"].append({
                    "issue": "Unclear fee distribution",
                    "description": "Fee distribution logic is opaque",
                    "risk": "Fees may not reach intended recipients"
                })
                issues_found += 1
        
        result["fee_scam_risk"] = issues_found >= 2
        
        return result
    
    def check_governance_manipulation(self, code: str, protocol_name: str) -> Dict[str, Any]:
        """Detect governance attacks and manipulation"""
        result = {
            "protocol": protocol_name,
            "governance_risk": False,
            "vulnerabilities": [],
            "attack_vectors": []
        }
        
        vulnerabilities = 0
        
        # Vulnerability 1: No voting delay
        if "vote" in code.lower() or "proposal" in code.lower():
            if "votingDelay" not in code and "voting_delay" not in code:
                result["vulnerabilities"].append("No voting delay - flash loan attack possible")
                result["attack_vectors"].append("Flash loan governance hijack")
                vulnerabilities += 1
        
        # Vulnerability 2: Single proposer
        if "propose" in code and "onlyOwner" in code:
            result["vulnerabilities"].append("Only owner can propose governance changes")
            result["attack_vectors"].append("Centralized proposal mechanism")
            vulnerabilities += 1
        
        # Vulnerability 3: Low quorum
        if "quorum" in code:
            if "require" in code and "<" in code:
                result["vulnerabilities"].append("Governance may have very low quorum requirement")
                result["attack_vectors"].append("Governance takeover with small vote percentage")
                vulnerabilities += 1
        
        # Vulnerability 4: No timelock
        if "execute" in code and "timelock" not in code.lower():
            if "onlyOwner" in code or "onlyGovernance" in code:
                result["vulnerabilities"].append("No timelock on governance execution")
                result["attack_vectors"].append("Instant governance execution - no escape window")
                vulnerabilities += 1
        
        # Vulnerability 5: Governance token manipulation
        if "mint" in code and ("governance" in code or "vote" in code):
            result["vulnerabilities"].append("Governance token can be minted")
            result["attack_vectors"].append("Dilution attack on voting power")
            vulnerabilities += 1
        
        result["governance_risk"] = vulnerabilities >= 2
        
        return result
    
    def generate_rugpull_score(self, security_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final rugpull risk score combining all indicators"""
        
        protocol = security_analysis.get("protocol", "Unknown")
        
        score_components = {
            "reward_risk": len(security_analysis["reward_distribution"]["red_flags"]) * 5,
            "treasury_risk": 25 if security_analysis["treasury_multisig"]["centralized"] else 10,
            "fee_risk": len(security_analysis["fee_collection"]["red_flags"]) * 4,
            "withdrawal_risk": 15 if security_analysis["staking_pool"]["has_restrictions"] else 5,
            "bridge_risk": len(security_analysis["bridge_contracts"]["red_flags"]) * 3,
            "governance_risk": 10 if security_analysis["governance"]["no_timelock"] else 0
        }
        
        total_score = min(sum(score_components.values()), 100)
        
        result = {
            "protocol": protocol,
            "rugpull_score": total_score,
            "risk_level": security_analysis.get("rugpull_risk_level", "UNKNOWN"),
            "investment_score": security_analysis.get("investment_score", 0),
            "risk_summary": security_analysis.get("risk_summary", ""),
            "score_breakdown": score_components,
            "recommendation": self._get_recommendation(total_score),
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        return result
    
    def _get_recommendation(self, score: float) -> str:
        """Get investment recommendation based on rugpull score"""
        if score >= 80:
            return "🚨 DO NOT INVEST - Extreme rugpull risk detected. Protocol shows critical governance vulnerabilities."
        elif score >= 65:
            return "⛔ AVOID - High rugpull risk. Multiple centralization and control vulnerabilities present."
        elif score >= 50:
            return "⚠️  CAUTION - Significant risks identified. Recommend thorough manual code review before any investment."
        elif score >= 30:
            return "📋 REVIEW - Moderate concerns present. Proceed with reduced investment amount and careful monitoring."
        elif score >= 15:
            return "✅ ACCEPTABLE - Low to moderate risk. Standard due diligence recommended."
        else:
            return "✅ LOW RISK - No major rugpull indicators detected in adapter analysis."
    
    def create_risk_report(self, security_analysis: Dict[str, Any], 
                          output_file: str = "rugpull_risk_report.json") -> Dict[str, Any]:
        """Create comprehensive rugpull risk report"""
        
        report = {
            "report_title": "🔒 DeFi Protocol Rugpull Risk Analysis Report",
            "generation_timestamp": datetime.now().isoformat(),
            "protocol": security_analysis.get("protocol", "Unknown"),
            
            "executive_summary": {
                "investment_score": security_analysis.get("investment_score", 0),
                "rugpull_risk_level": security_analysis.get("rugpull_risk_level", "UNKNOWN"),
                "recommendation": self._get_recommendation(security_analysis.get("investment_score", 0)),
                "risk_summary": security_analysis.get("risk_summary", "")
            },
            
            "critical_findings": {
                "reward_distribution": security_analysis["reward_distribution"]["red_flags"],
                "treasury_control": security_analysis["treasury_multisig"]["red_flags"],
                "fee_structure": security_analysis["fee_collection"]["red_flags"],
                "withdrawal_restrictions": security_analysis["staking_pool"]["red_flags"],
                "bridge_vulnerabilities": security_analysis["bridge_contracts"]["red_flags"],
                "governance_issues": [] if security_analysis["governance"]["no_timelock"] else []
            },
            
            "contract_analysis": {
                "reward_contracts": {
                    "count": len(security_analysis["reward_distribution"]["addresses"]),
                    "addresses": security_analysis["reward_distribution"]["addresses"],
                    "functions": security_analysis["reward_distribution"]["functions_found"]
                },
                "treasury_contracts": {
                    "count": len(security_analysis["treasury_multisig"]["addresses"]),
                    "addresses": security_analysis["treasury_multisig"]["addresses"],
                    "functions": security_analysis["treasury_multisig"]["functions_found"],
                    "control_type": "centralized" if security_analysis["treasury_multisig"]["centralized"] else "distributed"
                },
                "fee_contracts": {
                    "count": len(security_analysis["fee_collection"]["addresses"]),
                    "addresses": security_analysis["fee_collection"]["addresses"],
                    "functions": security_analysis["fee_collection"]["functions_found"],
                    "fee_percentages": security_analysis["fee_collection"]["fee_percentages"]
                },
                "staking_contracts": {
                    "count": len(security_analysis["staking_pool"]["addresses"]),
                    "addresses": security_analysis["staking_pool"]["addresses"],
                    "functions": security_analysis["staking_pool"]["functions_found"],
                    "has_restrictions": security_analysis["staking_pool"]["has_restrictions"]
                },
                "bridge_contracts": {
                    "count": len(security_analysis["bridge_contracts"]["addresses"]),
                    "addresses": security_analysis["bridge_contracts"]["addresses"],
                    "functions": security_analysis["bridge_contracts"]["functions_found"]
                }
            },
            
            "governance_analysis": {
                "access_controls": security_analysis["governance"]["access_control_patterns"],
                "has_timelock": not security_analysis["governance"]["no_timelock"],
                "has_multisig": not security_analysis["governance"]["no_multisig"],
                "centralization_score": security_analysis["governance"]["centralization_score"]
            },
            
            "investment_decision": {
                "safe_to_invest": security_analysis.get("investment_score", 0) < 40,
                "risk_score": security_analysis.get("investment_score", 0),
                "recommendation": self._get_recommendation(security_analysis.get("investment_score", 0))
            }
        }
        
        return report

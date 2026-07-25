import re
import json
from typing import Dict, List, Tuple, Any

class SecurityAnalyzer:
    """
    Comprehensive security analysis engine for detecting rugpull patterns,
    centralized control, fee siphoning, and governance vulnerabilities.
    """
    
    def __init__(self):
        # Contract variable patterns for identification
        self.reward_distributor_patterns = [
            r'reward[Dd]istributor\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'incentive[Dd]istributor\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'rewardManager\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'rewardPool\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'rewardVault\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
        ]
        
        self.treasury_multisig_patterns = [
            r'treasury\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'multisig\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'(?:^|\s)admin\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'(?:^|\s)owner\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'governance\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'timelock\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'governanceToken\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
        ]
        
        self.fee_collection_patterns = [
            r'feeCollector\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'feeDistributor\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'protocolFee\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'feeRecipient\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
        ]
        
        self.staking_pool_patterns = [
            r'stakingPool\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'(?:^|\s)pool\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'vault\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'lockVault\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'stakeToken\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'depositPool\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
        ]
        
        self.bridge_contract_patterns = [
            r'(?:^|\s)bridge\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'tokenBridge\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'bridgeContract\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'crossChainBridge\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'bridgeVault\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
            r'bridgeController\s*[:=]\s*["\']?(0x[a-fA-F0-9]{40})["\']?',
        ]
        
        # Critical function signatures to identify
        self.reward_functions = [
            'distributeRewards', 'claimRewards', 'getReward', 'pendingRewards',
            'emergencyWithdrawRewards', 'setRewardRate', 'rewardPerToken', 'earned'
        ]
        
        self.treasury_functions = [
            'withdraw', 'transfer', 'approve', 'executeTransaction', 'confirmTransaction',
            'revokeConfirmation', 'emergencyWithdraw', 'setAdmin', 'transferOwnership'
        ]
        
        self.fee_functions = [
            'collectFees', 'withdrawFees', 'setFeePercentage', 'claimFees',
            'emergencyFeeWithdraw', 'updateFeeRecipient', 'getFeeBalance', 'distributeFees'
        ]
        
        self.staking_functions = [
            'withdraw', 'unstake', 'redeem', 'deposit', 'emergencyWithdraw',
            'pause', 'unpause', 'setWithdrawalFee', 'getWithdrawalDelay',
            'lockWithdrawal'
        ]
        
        self.bridge_functions = [
            'withdraw', 'transferOut', 'claim', 'emergencyWithdraw', 'pauseBridge',
            'setBridgeValidator', 'setFeePercentage', 'lockFunds', 'releaseFunds'
        ]
        
        # Governance access control patterns
        self.governance_patterns = [
            r'onlyOwner',
            r'onlyAdmin',
            r'onlyGovernance',
            r'onlyMinter',
            r'onlyBurner',
            r'require\(msg\.sender == owner\)',
            r'require\(msg\.sender == admin\)',
            r'require\(hasRole\(ADMIN_ROLE, msg\.sender\)\)',
            r'require\(hasRole\(MINTER_ROLE, msg\.sender\)\)',
            r'require\(timelock\.delay\(\) > 0\)',
        ]
        
        # Fee percentage patterns
        self.fee_patterns = [
            r'fee[Pp]ercentage\s*[:=]\s*(\d+)',
            r'protocolFee\s*[:=]\s*(\d+)',
            r'withdrawalFee\s*[:=]\s*(\d+)',
            r'depositFee\s*[:=]\s*(\d+)',
        ]
    
    def extract_contract_addresses(self, code: str, pattern_list: List[str]) -> List[str]:
        """Extract unique contract addresses from code using regex patterns"""
        addresses = []
        for pattern in pattern_list:
            matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
            addresses.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_addresses = []
        for addr in addresses:
            if addr.lower() not in seen:
                seen.add(addr.lower())
                unique_addresses.append(addr)
        
        return unique_addresses
    
    def extract_functions(self, code: str, function_list: List[str]) -> List[str]:
        """Extract function signatures found in code"""
        found_functions = []
        for func in function_list:
            if re.search(rf'\b{func}\b', code, re.IGNORECASE):
                found_functions.append(func)
        return found_functions
    
    def extract_governance_patterns(self, code: str) -> List[str]:
        """Extract governance and access control patterns"""
        patterns = []
        for pattern in self.governance_patterns:
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                patterns.append(pattern.replace(r'\(', '(').replace(r'\)', ')'))
        return patterns
    
    def extract_fee_percentages(self, code: str) -> Dict[str, int]:
        """Extract fee percentages from code"""
        fees = {}
        for pattern in self.fee_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                fee_name = pattern.split(r'\s*[:=]')[0].strip()
                fees[fee_name] = int(match) if isinstance(match, str) else match
        return fees
    
    def detect_centralized_admin_control(self, governance_patterns: List[str], 
                                        code: str) -> Tuple[bool, List[str]]:
        """Detect if protocol has centralized admin control"""
        red_flags = []
        
        has_timelock = 'timelock' in str(governance_patterns).lower()
        has_multisig = 'multisig' in str(governance_patterns).lower()
        has_only_owner = any('onlyowner' in p.lower() for p in governance_patterns)
        
        if has_only_owner and not has_timelock:
            red_flags.append("Single admin can execute functions immediately (no timelock)")
        
        if has_only_owner and not has_multisig:
            red_flags.append("No multi-signature requirement on critical functions")
        
        # Check for emergency/admin transfer functions
        if re.search(r'emergencyWithdraw|adminTransfer|ownerWithdraw', code, re.IGNORECASE):
            red_flags.append("Emergency withdrawal functions found - could enable fund draining")
        
        is_centralized = has_only_owner and (not has_timelock or not has_multisig)
        
        return is_centralized, red_flags
    
    def detect_fee_siphoning(self, code: str, fee_percentages: Dict[str, int]) -> List[str]:
        """Detect suspicious fee structures that could indicate fund siphoning"""
        red_flags = []
        
        for fee_name, percentage in fee_percentages.items():
            if percentage > 10:
                red_flags.append(f"Unusually high fee detected: {fee_name} = {percentage}% (>10%)")
        
        # Check for uncapped fee withdrawal
        if re.search(r'withdrawFees|collectFees|claimFees', code, re.IGNORECASE):
            if not re.search(r'require.*maximum|require.*cap|maxFee', code, re.IGNORECASE):
                red_flags.append("No maximum cap on fee withdrawal - could enable unlimited fund siphoning")
        
        # Check for fee redistribution to single address
        if re.search(r'transfer.*to.*fee|send.*recipient.*fee', code, re.IGNORECASE):
            if re.search(r'single.*recipient|one.*address', code, re.IGNORECASE):
                red_flags.append("Fees distributed to single recipient - concentration risk")
        
        return red_flags
    
    def detect_withdrawal_restrictions(self, code: str, staking_addresses: List[str]) -> Tuple[bool, List[str]]:
        """Detect withdrawal restrictions that could trap user funds"""
        red_flags = []
        has_restrictions = False
        
        # Check for withdrawal locks
        if re.search(r'lockWithdrawal|withdrawalLock|freeze.*withdrawal', code, re.IGNORECASE):
            red_flags.append("Permanent or extended withdrawal locks detected")
            has_restrictions = True
        
        # Check for withdrawal delays
        if re.search(r'withdrawalDelay|lockTime|delay.*withdraw', code, re.IGNORECASE):
            delays = re.findall(r'withdrawalDelay\s*[:=]\s*(\d+)', code, re.IGNORECASE)
            for delay in delays:
                days = int(delay) // 86400 if int(delay) > 1000 else int(delay)
                if days > 30:
                    red_flags.append(f"Excessive withdrawal delay detected: {days} days (>30 days)")
                    has_restrictions = True
        
        # Check for paused withdrawal functions
        if re.search(r'pause.*withdraw|withdraw.*pause|withdrawalPaused', code, re.IGNORECASE):
            red_flags.append("Withdrawal functions can be paused - potential fund trap")
            has_restrictions = True
        
        # Check for emergency withdraw requirement
        if re.search(r'emergencyWithdraw', code, re.IGNORECASE):
            if not re.search(r'function emergencyWithdraw.*public', code, re.IGNORECASE):
                red_flags.append("Emergency withdrawal exists but may not be accessible")
                has_restrictions = True
        
        return has_restrictions, red_flags
    
    def detect_bridge_vulnerabilities(self, code: str, bridge_addresses: List[str]) -> List[str]:
        """Detect bridge contract vulnerabilities"""
        red_flags = []
        
        if not bridge_addresses:
            return red_flags
        
        # Check for rate limiting
        if not re.search(r'rateLimit|daily.*limit|hourly.*limit|max.*transfer', code, re.IGNORECASE):
            red_flags.append("No rate limiting on bridge withdrawals - enables unlimited fund extraction")
        
        # Check for pausing mechanism
        if re.search(r'pauseBridge|pauseWithdraw', code, re.IGNORECASE):
            red_flags.append("Bridge can be paused - could freeze user funds in transit")
        
        # Check for unilateral bridge control
        if re.search(r'setBridgeValidator|updateBridgeAddress', code, re.IGNORECASE):
            if re.search(r'onlyOwner|onlyAdmin', code, re.IGNORECASE):
                red_flags.append("Bridge parameters can be changed by single admin")
        
        # Check for bridge fee
        if re.search(r'bridgeFee|bridgePercentage', code, re.IGNORECASE):
            fees = re.findall(r'bridgeFee\s*[:=]\s*(\d+)', code, re.IGNORECASE)
            for fee in fees:
                if int(fee) > 5:
                    red_flags.append(f"High bridge fee detected: {fee}% - suspicious")
        
        return red_flags
    
    def detect_reward_distribution_anomalies(self, code: str, 
                                           reward_addresses: List[str]) -> List[str]:
        """Detect suspicious reward distribution patterns"""
        red_flags = []
        
        if not reward_addresses:
            return red_flags
        
        # Check if all rewards go to single address
        if len(reward_addresses) == 1:
            red_flags.append("All reward distribution concentrated to single address - centralization risk")
        
        # Check for zero reward scenarios
        if re.search(r'rewardRate\s*=\s*0|reward.*disabled|reward.*stopped', code, re.IGNORECASE):
            red_flags.append("Reward distribution can be disabled without notice")
        
        # Check for reward lock-up
        if re.search(r'rewardLock|lockReward|reward.*freeze', code, re.IGNORECASE):
            red_flags.append("Rewards can be locked - prevents user claims")
        
        # Check for clawback mechanism
        if re.search(r'clawback.*reward|slashReward|penalizeReward', code, re.IGNORECASE):
            red_flags.append("Protocol can clawback user rewards - high risk")
        
        # Check for reward manipulation
        if re.search(r'setRewardRate|updateRewardPercentage', code, re.IGNORECASE):
            if re.search(r'onlyOwner|onlyAdmin', code, re.IGNORECASE):
                red_flags.append("Reward rate can be changed by single admin without timelock")
        
        return red_flags
    
    def calculate_investment_score(self, analysis: Dict[str, Any]) -> float:
        """
        Calculate investment score based on security indicators
        Higher score = higher risk/less trustworthy
        Max score = 100
        """
        score = 0
        
        # Reward distribution analysis (25 points max)
        if analysis['reward_distribution']['red_flags']:
            score += 25
        
        # Treasury/multisig analysis (25 points max)
        if analysis['treasury_multisig']['centralized']:
            score += 25
        elif analysis['treasury_multisig']['red_flags']:
            score += 15
        
        # Fee collection analysis (20 points max)
        if analysis['fee_collection']['red_flags']:
            score += 20
        
        # Staking pool analysis (15 points max)
        if analysis['staking_pool']['has_restrictions']:
            score += 15
        
        # Bridge contract analysis (10 points max)
        if analysis['bridge_contracts']['red_flags']:
            score += 10
        
        # Governance analysis (5 points max)
        if analysis['governance']['no_timelock']:
            score += 5
        
        return min(score, 100.0)
    
    def determine_rugpull_risk(self, score: float) -> str:
        """Determine rugpull risk level based on investment score"""
        if score >= 75:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def analyze_protocol(self, protocol_name: str, adapter_code: str) -> Dict[str, Any]:
        """
        Comprehensive security analysis of a single protocol
        """
        
        # Extract all contract addresses
        reward_addresses = self.extract_contract_addresses(adapter_code, self.reward_distributor_patterns)
        treasury_addresses = self.extract_contract_addresses(adapter_code, self.treasury_multisig_patterns)
        fee_addresses = self.extract_contract_addresses(adapter_code, self.fee_collection_patterns)
        staking_addresses = self.extract_contract_addresses(adapter_code, self.staking_pool_patterns)
        bridge_addresses = self.extract_contract_addresses(adapter_code, self.bridge_contract_patterns)
        
        # Extract functions
        reward_functions = self.extract_functions(adapter_code, self.reward_functions)
        treasury_functions = self.extract_functions(adapter_code, self.treasury_functions)
        fee_functions = self.extract_functions(adapter_code, self.fee_functions)
        staking_functions = self.extract_functions(adapter_code, self.staking_functions)
        bridge_functions = self.extract_functions(adapter_code, self.bridge_functions)
        
        # Extract governance patterns
        governance_patterns = self.extract_governance_patterns(adapter_code)
        
        # Extract fee percentages
        fee_percentages = self.extract_fee_percentages(adapter_code)
        
        # Analyze governance
        is_centralized, centralization_flags = self.detect_centralized_admin_control(
            governance_patterns, adapter_code
        )
        
        # Analyze fees
        fee_flags = self.detect_fee_siphoning(adapter_code, fee_percentages)
        
        # Analyze staking pools
        has_restrictions, restriction_flags = self.detect_withdrawal_restrictions(
            adapter_code, staking_addresses
        )
        
        # Analyze bridge
        bridge_flags = self.detect_bridge_vulnerabilities(adapter_code, bridge_addresses)
        
        # Analyze rewards
        reward_flags = self.detect_reward_distribution_anomalies(adapter_code, reward_addresses)
        
        # Build analysis dictionary
        analysis = {
            "protocol": protocol_name,
            "reward_distribution": {
                "addresses": reward_addresses,
                "functions_found": reward_functions,
                "red_flags": reward_flags,
                "risk_score": len(reward_flags) * 5.0
            },
            "treasury_multisig": {
                "addresses": treasury_addresses,
                "functions_found": treasury_functions,
                "centralized": is_centralized,
                "red_flags": centralization_flags,
                "risk_score": (25 if is_centralized else 10) + len(centralization_flags) * 2
            },
            "fee_collection": {
                "addresses": fee_addresses,
                "functions_found": fee_functions,
                "fee_percentages": fee_percentages,
                "red_flags": fee_flags,
                "risk_score": len(fee_flags) * 3.0
            },
            "staking_pool": {
                "addresses": staking_addresses,
                "functions_found": staking_functions,
                "has_restrictions": has_restrictions,
                "red_flags": restriction_flags,
                "risk_score": (15 if has_restrictions else 5) + len(restriction_flags) * 3
            },
            "bridge_contracts": {
                "addresses": bridge_addresses,
                "functions_found": bridge_functions,
                "red_flags": bridge_flags,
                "risk_score": len(bridge_flags) * 4.0
            },
            "governance": {
                "access_control_patterns": governance_patterns,
                "no_timelock": not any('timelock' in p.lower() for p in governance_patterns),
                "no_multisig": not any('multisig' in p.lower() for p in governance_patterns),
                "centralization_score": 8.5 if is_centralized else 3.0
            }
        }
        
        # Calculate investment score
        investment_score = self.calculate_investment_score(analysis)
        analysis["investment_score"] = investment_score
        analysis["rugpull_risk_level"] = self.determine_rugpull_risk(investment_score)
        
        # Generate risk summary
        total_red_flags = (
            len(reward_flags) + len(centralization_flags) + 
            len(fee_flags) + len(restriction_flags) + len(bridge_flags)
        )
        
        if total_red_flags >= 5:
            analysis["risk_summary"] = f"🚨 CRITICAL: {total_red_flags} security red flags detected. Protocol shows multiple centralization vulnerabilities and rugpull indicators."
        elif total_red_flags >= 3:
            analysis["risk_summary"] = f"⚠️  HIGH RISK: {total_red_flags} security issues identified. Multiple governance and control vulnerabilities present."
        elif total_red_flags >= 1:
            analysis["risk_summary"] = f"⚡ MEDIUM RISK: {total_red_flags} security concern(s) found. Review recommended before investment."
        else:
            analysis["risk_summary"] = "✅ LOW RISK: No major security red flags detected in adapter code analysis."
        
        return analysis

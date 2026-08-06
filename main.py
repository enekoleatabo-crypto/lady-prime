import os
import json
import requests
import time
from dotenv import load_dotenv
from datetime import datetime
from security_orchestrator import SecurityOrchestrator

# Load environment variables
load_dotenv()

GITHUB_PAT = os.getenv("GITHUB_PAT")
GITHUB_API_URL = "https://api.github.com"
DEFILLAMA_REPO = "DefiLlama/DefiLlama-Adapters"

# Headers for GitHub API authentication
HEADERS = {
    "Authorization": f"token {GITHUB_PAT}",
    "Accept": "application/vnd.github.v3+json"
}

# Known liquid staking protocol keywords to filter
LIQUID_STAKING_KEYWORDS = [
    "lido", "steth", "reth", "rocket", "stakewise", "frxeth", "frax", 
    "sfrxeth", "eigen", "eigenlayer", "puffer", "mellow", "instadapp",
    "symbiotic", "karak", "restake", "pendle", "aave", "morpho",
    "yearn", "convex", "stake", "liquid", "lsp", "kelp", "lst"
]

class DefiLlamaAdapterFetcher:
    """
    Fetches liquid staking protocol adapters from DefiLlama-Adapters repository.
    Extracts contract addresses and prepares data for security analysis.
    """
    
    def __init__(self):
        self.protocols = []
        self.rate_limit_remaining = None
        
    def get_rate_limit_info(self):
        """Check remaining API rate limit"""
        try:
            url = f"{GITHUB_API_URL}/rate_limit"
            response = requests.get(url, headers=HEADERS)
            if response.status_code == 200:
                data = response.json()
                self.rate_limit_remaining = data['rate']['remaining']
                return data['rate']
            return None
        except:
            return None
    
    def get_all_projects_in_adapters(self):
        """
        Fetch all protocol directories from /projects folder
        """
        print("\n🔍 Fetching all protocol adapters from /projects directory...")
        
        try:
            url = f"{GITHUB_API_URL}/repos/{DEFILLAMA_REPO}/contents/projects"
            
            print(f"   Requesting: {url}")
            response = requests.get(url, headers=HEADERS)
            
            if response.status_code == 404:
                print(f"❌ 404 Error: /projects directory not found")
                return []
            
            response.raise_for_status()
            
            adapters = response.json()
            
            # Filter only directories (protocols)
            protocol_dirs = [item for item in adapters if item["type"] == "dir"]
            
            print(f"✅ Found {len(protocol_dirs)} protocol directories")
            
            return protocol_dirs
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching adapters: {e}")
            return []
    
    def is_liquid_staking_protocol(self, protocol_name):
        """Check if protocol name matches liquid staking keywords"""
        name_lower = protocol_name.lower()
        return any(keyword in name_lower for keyword in LIQUID_STAKING_KEYWORDS)
    
    def parse_protocol_adapter(self, protocol_dir):
        """Parse individual protocol to extract contract addresses"""
        try:
            protocol_name = protocol_dir["name"]
            
            # Get the index.js file from protocol directory
            index_url = f"{GITHUB_API_URL}/repos/{DEFILLAMA_REPO}/contents/projects/{protocol_name}/index.js"
            
            response = requests.get(index_url, headers=HEADERS)
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            
            file_data = response.json()
            
            # Get raw content
            raw_content = requests.get(file_data["download_url"]).text
            
            # Extract contract addresses
            contracts = self._extract_contract_addresses(raw_content)
            
            return {
                "protocol": protocol_name,
                "github_url": f"https://github.com/{DEFILLAMA_REPO}/tree/main/projects/{protocol_name}",
                "index_file_url": file_data["html_url"],
                "contracts": contracts,
            }
            
        except requests.exceptions.RequestException:
            return None
    
    def _extract_contract_addresses(self, content):
        """Extract and categorize contract addresses from code"""
        import re
        
        contracts = {
            "stake_contracts": [],
            "reward_contracts": [],
            "withdrawal_contracts": [],
            "other_contracts": []
        }
        
        # Find all Ethereum addresses (0x + 40 hex chars)
        address_pattern = r'0x[a-fA-F0-9]{40}'
        addresses = re.findall(address_pattern, content)
        
        # Remove duplicates
        unique_addresses = list(set(addresses))
        
        # Categorize by context
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for address in unique_addresses:
                if address.lower() not in str(contracts).lower():  # Skip if already categorized
                    if address in line:
                        context_start = max(0, i - 2)
                        context_end = min(len(lines), i + 3)
                        context = ' '.join(lines[context_start:context_end]).lower()
                        
                        if any(kw in context for kw in ['stake', 'staking', 'deposit', 'lsp']):
                            contracts["stake_contracts"].append(address)
                        elif any(kw in context for kw in ['reward', 'incentive', 'fee']):
                            contracts["reward_contracts"].append(address)
                        elif any(kw in context for kw in ['withdraw', 'unstake', 'claim']):
                            contracts["withdrawal_contracts"].append(address)
                        else:
                            contracts["other_contracts"].append(address)
        
        return contracts
    
    def fetch_all_adapters(self):
        """Fetch all liquid staking protocol adapters"""
        protocol_dirs = self.get_all_projects_in_adapters()
        
        if not protocol_dirs:
            print("❌ No protocol directories found!")
            return []
        
        print(f"\n📋 Scanning {len(protocol_dirs)} protocols for liquid staking...")
        
        liquid_staking_count = 0
        for i, protocol_dir in enumerate(protocol_dirs, 1):
            protocol_name = protocol_dir["name"]
            
            if self.is_liquid_staking_protocol(protocol_name):
                print(f"  [{i}/{len(protocol_dirs)}] 🔗 {protocol_name}...", end=" ", flush=True)
                
                parsed = self.parse_protocol_adapter(protocol_dir)
                if parsed:
                    self.protocols.append(parsed)
                    liquid_staking_count += 1
                    print("✓")
                else:
                    print("✗")
                
                time.sleep(0.1)  # Avoid rate limiting
            elif i % 50 == 0:
                print(f"  [{i}/{len(protocol_dirs)}] Scanning...")
        
        print(f"\n✅ Found {len(self.protocols)} liquid staking protocol adapters")
        return self.protocols
    
    def save_results(self, filename="liquid_staking_analysis.json"):
        """Save results to JSON file"""
        output_data = {
            "metadata": {
                "title": "Liquid Staking Protocols - Contract Analysis",
                "extracted_at": datetime.now().isoformat(),
                "total_protocols_found": len(self.protocols),
                "data_source": "DefiLlama-Adapters GitHub Repository"
            },
            "protocols": self.protocols,
        }
        
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"💾 Results saved to {filename}")
    
    def display_results(self):
        """Display extracted protocol information"""
        print("\n" + "="*80)
        print("LIQUID STAKING PROTOCOLS - CONTRACT ADDRESSES")
        print("="*80 + "\n")
        
        if not self.protocols:
            print("⚠️  No liquid staking protocols found!")
            return
        
        for idx, protocol in enumerate(self.protocols, 1):
            print(f"{idx}. 📋 {protocol['protocol']}")
            print(f"   GitHub: {protocol['github_url']}")
            print(f"   Index: {protocol['index_file_url']}")
            
            contracts = protocol['contracts']
            total = sum(len(v) for v in contracts.values())
            print(f"   Total Contracts: {total}")
            
            if contracts['stake_contracts']:
                print(f"   🔒 Stake: {', '.join(contracts['stake_contracts'][:2])}")
            if contracts['reward_contracts']:
                print(f"   💰 Rewards: {', '.join(contracts['reward_contracts'][:2])}")
            if contracts['withdrawal_contracts']:
                print(f"   🚀 Withdrawal: {', '.join(contracts['withdrawal_contracts'][:2])}")
            
            print()


def run_protocol_discovery():
    """Step 1: Discover and fetch protocols"""
    print("\n" + "="*80)
    print("🚀 LADY PRIME - DeFi SECURITY & RUGPULL ANALYSIS ENGINE v2.0")
    print("="*80)
    print("\n[STEP 1/2] Protocol Discovery & Contract Extraction")
    print("="*80)
    
    if not GITHUB_PAT:
        print("❌ Error: GITHUB_PAT not found in .env file")
        print("   Add to .env: GITHUB_PAT=your_token_here")
        return False
    
    fetcher = DefiLlamaAdapterFetcher()
    
    rate_limit = fetcher.get_rate_limit_info()
    if rate_limit:
        print(f"📊 Rate Limit: {rate_limit['remaining']}/{rate_limit['limit']} requests remaining")
    
    fetcher.fetch_all_adapters()
    fetcher.display_results()
    fetcher.save_results("liquid_staking_analysis.json")
    
    return True


def run_security_analysis():
    """Step 2: Analyze protocols for security and rugpull risks"""
    print("\n" + "="*80)
    print("[STEP 2/2] Security Analysis & Rugpull Detection")
    print("="*80)
    
    # Initialize orchestrator
    orchestrator = SecurityOrchestrator("liquid_staking_analysis.json")
    
    # Run full analysis pipeline
    orchestrator.run_full_analysis()
    
    return True


def main():
    """Main entry point - runs complete pipeline"""
    try:
        # Step 1: Protocol Discovery
        if not run_protocol_discovery():
            print("\n❌ Protocol discovery failed. Exiting.")
            return
        
        # Step 2: Security Analysis
        if not run_security_analysis():
            print("\n❌ Security analysis failed.")
            return
        
        print("\n" + "="*80)
        print("✨ LADY PRIME ANALYSIS COMPLETE")
        print("="*80)
        print("\n📁 Generated Files:")
        print("   📊 liquid_staking_analysis.json - Raw protocol data from DefiLlama")
        print("   🔒 security_analysis_report.json - Comprehensive security analysis")
        print("   📈 security_analysis_report.csv - Spreadsheet for analysis")
        print("   ⚠️  risk_rankings.json - Protocol rankings by risk level")
        print("   📋 protocol_reports/ - Individual detailed reports per protocol")
        print("\n🚨 Review reports to identify:")
        print("   ✓ Centralized admin control")
        print("   ✓ Fee siphoning mechanisms")
        print("   ✓ Withdrawal traps and locks")
        print("   ✓ Bridge vulnerabilities")
        print("   ✓ Reward distribution anomalies")
        print("   ✓ Governance manipulation vectors")
        print("\n🔍 Use rankings to prioritize HIGH & CRITICAL risk protocols!")
        print("="*80 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

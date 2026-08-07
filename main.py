import os
import json
import requests
import time
import re
import html
from collections import defaultdict
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

# Detection helpers / heuristics
ADDRESS_REGEX = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
KEYWORD_TO_CATEGORY = {
    'stake': 'stake_contracts',
    'staking': 'stake_contracts',
    'staked': 'stake_contracts',
    'reward': 'reward_contracts',
    'rewards': 'reward_contracts',
    'withdraw': 'withdrawal_contracts',
    'withdrawal': 'withdrawal_contracts',
    'vault': 'vault_contracts',
    'chef': 'chef_contracts',
    'owner': 'owner_addresses',
    'admin': 'admin_addresses',
    'governor': 'governance_addresses',
    'liquid': 'liquid_contracts',
    'pool2': 'pool2_contracts',
    'fee': 'fee_related',
}

SECURITY_KEYWORDS = [
    'onlyOwner', 'transferOwnership', 'setFee', 'pause', 'unpause',
    'renounceOwnership', 'multisig', 'owner.withdraw', "require(msg.sender == owner)",
    'initialize(', 'proxy', 'upgrade', 'setAdmin', 'setOwner', 'setGovernor'
]

GITHUB_CONTENTS_BASE = f"{GITHUB_API_URL}/repos/{DEFILLAMA_REPO}/contents/"


def extract_addresses_from_text(text: str):
    text = html.unescape(text)
    return ADDRESS_REGEX.findall(text)


def classify_address_by_context(text: str, addr_index: int, address: str):
    N = 200
    start = max(0, addr_index - N)
    end = min(len(text), addr_index + len(address) + N)
    ctx = text[start:end].lower()
    categories = set()
    for kw, cat in KEYWORD_TO_CATEGORY.items():
        if kw in ctx:
            categories.add(cat)
    return categories


def scan_adapter_files_for_addresses(adapter_path: str, token: str, file_exts=None, max_files=50):
    if file_exts is None:
        file_exts = ('.js', '.ts', '.mjs', '.cjs', '.json', '.sol')

    headers = HEADERS.copy()
    # Use GitHub API listing for the folder
    url = GITHUB_CONTENTS_BASE + adapter_path
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 404:
            return {'error': 'adapter-path-not-found'}
        r.raise_for_status()
    except Exception as e:
        return {'error': str(e)}

    try:
        items = r.json()
    except Exception as e:
        return {'error': 'bad-json-listing'}

    results = defaultdict(list)
    files_scanned = 0

    # items may be a single file dict or a list
    if isinstance(items, dict) and items.get('type') == 'file':
        items = [items]

    for item in items:
        if files_scanned >= max_files:
            break
        if item.get('type') != 'file':
            # If it's a directory, skip (we only scan top-level files in adapter dir for now)
            continue
        name = item.get('name', '')
        if not any(name.endswith(ext) for ext in file_exts):
            continue
        raw_url = item.get('download_url')
        if not raw_url:
            continue
        files_scanned += 1
        try:
            rf = requests.get(raw_url, headers=headers, timeout=30)
            rf.raise_for_status()
            text = rf.text
        except Exception:
            continue

        # extract all addresses and classify by local context
        for m in ADDRESS_REGEX.finditer(text):
            addr = m.group(0)
            categories = classify_address_by_context(text, m.start(), addr)
            if not categories:
                results['candidates'].append((addr, name, 'regex'))
            else:
                for c in categories:
                    results[c].append((addr, name, 'regex_context'))

        # security heuristics scan
        lowered = text.lower()
        for sk in SECURITY_KEYWORDS:
            if sk.lower() in lowered:
                results['security_flags'].append((sk, name))

        time.sleep(0.08)

    return results


def augment_and_print_protocol(protocol: dict, github_token: str):
    name = protocol.get('protocol') or protocol.get('name') or 'UNKNOWN'
    path = protocol.get('path') or f"projects/{protocol.get('protocol') or protocol.get('name')}"
    contracts = protocol.get('contracts') or {}

    # ensure expected keys exist
    for k in ['stake_contracts', 'reward_contracts', 'withdrawal_contracts', 'owner_addresses', 'candidates']:
        contracts.setdefault(k, [])

    total = sum(len(v) for v in contracts.values() if isinstance(v, list))

    print(f"1. 📋 {name}")
    if path:
        print(f"   GitHub: https://github.com/{DEFILLAMA_REPO}/tree/main/{path}")
    print(f"   Total Contracts (initial): {total}")

    should_scan = (total == 0) or (total < 2)
    scan_results = {}
    if should_scan and path:
        scan_results = scan_adapter_files_for_addresses(path, github_token)
        if 'error' in scan_results:
            print(f"   ⚠️ Adapter scan failed: {scan_results['error']}")
            scan_results = {}
        else:
            for cat, items in list(scan_results.items()):
                if cat in ['security_flags', 'error']:
                    continue
                for addr, srcfile, method in items:
                    entry = f"{addr} ({srcfile}|{method})"
                    if cat == 'stake_contracts' or 'stake' in cat:
                        dest = 'stake_contracts'
                    elif cat == 'reward_contracts' or 'reward' in cat:
                        dest = 'reward_contracts'
                    elif cat == 'withdrawal_contracts' or 'withdraw' in cat:
                        dest = 'withdrawal_contracts'
                    elif cat == 'owner_addresses':
                        dest = 'owner_addresses'
                    elif cat == 'candidates':
                        dest = 'candidates'
                    else:
                        dest = cat
                    if entry not in contracts.get(dest, []):
                        contracts.setdefault(dest, []).append(entry)

            flags = scan_results.get('security_flags', [])
            if flags:
                print("   🔎 Security heuristics found patterns:")
                for sk, filename in flags:
                    print(f"     - {sk} in {filename}")

            total = sum(len(v) for v in contracts.values() if isinstance(v, list))

    print(f"   Total Contracts (final): {total}")

    def print_list_label(key, label, limit=5):
        arr = contracts.get(key, []) or []
        if arr:
            displayed = arr[:limit]
            more = len(arr) - len(displayed)
            print(f"   {label}: {', '.join(displayed)}{(' ...+'+str(more)+' more' ) if more>0 else ''}")

    print_list_label('stake_contracts', '🔒 Stake')
    print_list_label('reward_contracts', '💰 Rewards')
    print_list_label('withdrawal_contracts', '🚀 Withdrawal')
    print_list_label('owner_addresses', '👤 Owners / Admins')
    print_list_label('candidates', '❓ Candidate addresses (unclassified)')

    alerts = []
    if contracts.get('owner_addresses') and len(contracts.get('owner_addresses')) == 1:
        alerts.append("Ownership concentrated: single owner address found")
    if 'candidates' in contracts and len(contracts['candidates']) > 5:
        alerts.append("Many candidate addresses found — adapter might expose many contracts not categorized")
    if scan_results.get('security_flags'):
        alerts.append("Code contains ownership/onlyOwner/pause/upgrade patterns — investigate")

    if alerts:
        print("   ⚠️ Security Flags Summary:")
        for a in alerts:
            print(f"     - {a}")

    print()

    protocol['contracts'] = contracts
    return protocol


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
            path = f"projects/{protocol_name}"
            # Get the index.js file from protocol directory
            index_url = f"{GITHUB_API_URL}/repos/{DEFILLAMA_REPO}/contents/{path}/index.js"
            
            response = requests.get(index_url, headers=HEADERS)
            
            if response.status_code == 404:
                # No index.js present, still return a protocol entry with empty contracts so augmenter can scan files
                return {
                    "protocol": protocol_name,
                    "path": path,
                    "github_url": f"https://github.com/{DEFILLAMA_REPO}/tree/main/{path}",
                    "index_file_url": None,
                    "contracts": {
                        "stake_contracts": [],
                        "reward_contracts": [],
                        "withdrawal_contracts": [],
                        "other_contracts": []
                    }
                }
            
            response.raise_for_status()
            
            file_data = response.json()
            
            # Get raw content
            raw_content = requests.get(file_data["download_url"], headers=HEADERS).text
            
            # Extract contract addresses
            contracts = self._extract_contract_addresses(raw_content)
            
            return {
                "protocol": protocol_name,
                "path": path,
                "github_url": f"https://github.com/{DEFILLAMA_REPO}/tree/main/{path}",
                "index_file_url": file_data["html_url"],
                "contracts": contracts,
            }
            
        except requests.exceptions.RequestException:
            return None
    
    def _extract_contract_addresses(self, content):
        """Extract and categorize contract addresses from code"""
        contracts = {
            "stake_contracts": [],
            "reward_contracts": [],
            "withdrawal_contracts": [],
            "other_contracts": []
        }
        
        # Find all Ethereum addresses (0x + 40 hex chars)
        addresses = ADDRESS_REGEX.findall(content)
        
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
            # Use the augmenter to scan/augment and print richer output
            augment_and_print_protocol(protocol, GITHUB_PAT)


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

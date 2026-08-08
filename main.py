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

# Discovery keywords: broadened per research guidance
DISCOVERY_KEYWORDS = [
    "withdraw","reward","treasury","incentive","fee","claim","unstake","owner","admin","governance","vault",
    "payment","distribute","allocation","release","transfer","send","disburse","expenditure",
    "fund","finance","financial","treasury","balance","asset","token","coin","crypto",
    "wallet","account","escrow","custody","deposit","withdrawal","claimable","claiming",
    "rewards","earnings","profit","distribution","dividend","interest","yield"
]

# Additional address categories (for analysis downstream)
EXTRA_CATEGORIES = [
    "payment_addresses",
    "escrow_addresses",
    "custody_addresses",
    "distribution_addresses",
    "allocation_addresses",
    "transfer_addresses"
]

# Scan controls
LIMIT = 500           # Test on first N project entries
FULL_SCAN = True      # If True: allow more exhaustive per-project file scanning
PRIORITY_CATEGORIES = ["payment","withdrawal","treasury","reward","escrow","custody","governance"]

class DefiLlamaAdapterFetcher:
    """
    Fetches protocol adapters from DefiLlama-Adapters repository.
    Broad discovery: single-file adapters + content-based detection focusing on financial keywords.
    """
    
    def __init__(self):
        self.protocols = []
        self.rate_limit_remaining = None
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.request_delay = 0.08
    
    def get_rate_limit_info(self):
        try:
            url = f"{GITHUB_API_URL}/rate_limit"
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                self.rate_limit_remaining = data['rate']['remaining']
                return data['rate']
            return None
        except Exception:
            return None
    
    def get_all_projects_in_adapters(self):
        print("\n🔍 Fetching all protocol adapters from /projects directory...")
        try:
            url = f"{GITHUB_API_URL}/repos/{DEFILLAMA_REPO}/contents/projects"
            print(f"   Requesting: {url}")
            response = self.session.get(url)
            if response.status_code == 404:
                print("❌ 404 Error: /projects directory not found")
                return []
            response.raise_for_status()
            adapters = response.json()
            protocol_entries = [item for item in adapters if item.get("type") in ("dir","file")]
            print(f"✅ Found {len(protocol_entries)} project entries (dirs+files)")
            return protocol_entries
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching adapters: {e}")
            return []
    
    def _fetch_file_text(self, api_item):
        try:
            download_url = api_item.get("download_url")
            if download_url:
                r = self.session.get(download_url)
                if r.status_code == 200:
                    return r.text
                return None
            url = api_item.get("url")
            if not url:
                return None
            r = self.session.get(url)
            if r.status_code == 200:
                data = r.json()
                if data.get("encoding") == "base64" and data.get("content"):
                    import base64
                    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            return None
        except Exception:
            return None
    
    def is_protocol_of_interest(self, entry):
        import re
        address_pattern = r'0x[a-fA-F0-9]{40}'
        try:
            if entry["type"] == "file":
                text = self._fetch_file_text(entry)
                time.sleep(self.request_delay)
                if not text:
                    return False
                if re.search(address_pattern, text) or any(k in text.lower() for k in DISCOVERY_KEYWORDS):
                    return True
                return False
            url = f"{GITHUB_API_URL}/repos/{DEFILLAMA_REPO}/contents/projects/{entry['name']}"
            r = self.session.get(url)
            time.sleep(self.request_delay)
            if r.status_code != 200:
                return False
            items = r.json()
            for it in items:
                if it.get('type') == 'file' and it.get('name','').lower().endswith(('.js','.ts')):
                    text = self._fetch_file_text(it)
                    time.sleep(self.request_delay)
                    if not text:
                        continue
                    if re.search(address_pattern, text) or any(k in text.lower() for k in DISCOVERY_KEYWORDS):
                        return True
            return False
        except Exception:
            return False
    
    def parse_protocol_adapter(self, entry):
        import re
        address_pattern = r'0x[a-fA-F0-9]{40}'
        categorized = {
            "reward_addresses": [],
            "withdrawal_addresses": [],
            "treasury_addresses": [],
            "governance_addresses": [],
            "staking_addresses": []
        }
        # include extra categories in output structure (empty for now)
        for c in EXTRA_CATEGORIES:
            categorized[c] = []
        try:
            if entry['type'] == 'file':
                protocol_name = entry['name'].rsplit('.',1)[0]
                text = self._fetch_file_text(entry) or ''
                addresses = list(set(re.findall(address_pattern, text)))
                lines = text.split('\n')
                for addr in addresses:
                    for i, line in enumerate(lines):
                        if addr in line:
                            context = ' '.join(lines[max(0,i-2):min(len(lines),i+3)]).lower()
                            if any(k in context for k in ['reward','incentive','fee','rewards','earnings']):
                                categorized['reward_addresses'].append(addr)
                            elif any(k in context for k in ['withdraw','unstake','claim','withdrawal']):
                                categorized['withdrawal_addresses'].append(addr)
                            elif any(k in context for k in ['treasury','treasury_address','treasurywallet','fund','finance','custody','escrow']):
                                categorized['treasury_addresses'].append(addr)
                            elif any(k in context for k in ['governance','gov','proposal','executor','timelock','owner','admin']):
                                categorized['governance_addresses'].append(addr)
                            elif any(k in context for k in ['stake','staking','lsp']):
                                categorized['staking_addresses'].append(addr)
                            elif any(k in context for k in ['payment','send','transfer','disburse','distribute','allocation','release']):
                                categorized['payment_addresses'].append(addr)
                            else:
                                categorized['treasury_addresses'].append(addr)
                return {
                    'protocol': protocol_name,
                    'adapter_url': entry.get('html_url') if entry.get('html_url') else f"https://github.com/{DEFILLAMA_REPO}/tree/main/projects/{entry['name']}",
                    **categorized
                }
            # directory
            protocol_name = entry['name']
            url = f"{GITHUB_API_URL}/repos/{DEFILLAMA_REPO}/contents/projects/{protocol_name}"
            r = self.session.get(url)
            time.sleep(self.request_delay)
            if r.status_code != 200:
                return None
            items = r.json()
            combined_text = ''
            # if FULL_SCAN is True, scan all files; otherwise only top-level .js/.ts
            for it in items:
                if it.get('type') == 'file' and (FULL_SCAN or it.get('name','').lower().endswith(('.js','.ts'))):
                    txt = self._fetch_file_text(it) or ''
                    time.sleep(self.request_delay)
                    combined_text += '\n' + txt
            if not combined_text:
                return None
            addresses = list(set(re.findall(address_pattern, combined_text)))
            lines = combined_text.split('\n')
            for addr in addresses:
                for i, line in enumerate(lines):
                    if addr in line:
                        context = ' '.join(lines[max(0,i-2):min(len(lines),i+3)]).lower()
                        if any(k in context for k in ['reward','incentive','fee','rewards','earnings']):
                            categorized['reward_addresses'].append(addr)
                        elif any(k in context for k in ['withdraw','unstake','claim','withdrawal']):
                            categorized['withdrawal_addresses'].append(addr)
                        elif any(k in context for k in ['treasury','treasury_address','treasurywallet','fund','finance','custody','escrow']):
                            categorized['treasury_addresses'].append(addr)
                        elif any(k in context for k in ['governance','gov','proposal','executor','timelock','owner','admin']):
                            categorized['governance_addresses'].append(addr)
                        elif any(k in context for k in ['stake','staking','lsp']):
                            categorized['staking_addresses'].append(addr)
                        elif any(k in context for k in ['payment','send','transfer','disburse','distribute','allocation','release']):
                            categorized['payment_addresses'].append(addr)
                        else:
                            categorized['treasury_addresses'].append(addr)
            return {
                'protocol': protocol_name,
                'adapter_url': f"https://github.com/{DEFILLAMA_REPO}/tree/main/projects/{protocol_name}",
                **{k: list(dict.fromkeys(v)) for k,v in categorized.items()}
            }
        except Exception:
            return None
    
    def fetch_all_adapters(self):
        entries = self.get_all_projects_in_adapters()
        if not entries:
            print("❌ No protocol entries found!")
            return []
        print(f"\n📋 Scanning up to {LIMIT} project entries for addresses / keywords...")
        entries_to_scan = entries[:LIMIT]
        for i, entry in enumerate(entries_to_scan, 1):
            print(f"  [{i}/{len(entries_to_scan)}] Checking {entry.get('name')} ({entry.get('type')})...", end=' ', flush=True)
            try:
                if self.is_protocol_of_interest(entry):
                    parsed = self.parse_protocol_adapter(entry)
                    if parsed:
                        self.protocols.append(parsed)
                        print('✓')
                    else:
                        print('✗ (no parse)')
                else:
                    print('✗')
            except Exception as e:
                print(f'err: {e}')
            time.sleep(self.request_delay)
            if i % 100 == 0:
                print(f"  Scanned {i} entries so far...")
        print(f"\n✅ Found {len(self.protocols)} protocol adapters with addresses/keywords")
        return self.protocols
    
    def save_results(self, filename="liquid_staking_analysis.json"):
        output_data = {
            "metadata": {
                "title": "Protocol Address Extraction (broadened)",
                "extracted_at": datetime.now().isoformat(),
                "total_protocols_found": len(self.protocols),
                "data_source": "DefiLlama-Adapters GitHub Repository (/projects directory)",
                "discovery_keywords": DISCOVERY_KEYWORDS,
                "limit": LIMIT,
                "full_scan": FULL_SCAN,
                "priority_categories": PRIORITY_CATEGORIES
            },
            "protocols": self.protocols,
        }
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"💾 Results saved to {filename}")
    
    def display_results(self):
        print("\n" + "="*80)
        print("PROTOCOLS - CONTRACT ADDRESSES (by category)")
        print("="*80 + "\n")
        if not self.protocols:
            print("⚠️  No protocols found!")
            return
        for idx, protocol in enumerate(self.protocols, 1):
            print(f"{idx}. {protocol['protocol']}")
            total = sum(len(v) for k,v in protocol.items() if k.endswith('_addresses'))
            print(f"   Total addresses: {total}")
            for cat in ['treasury_addresses','reward_addresses','withdrawal_addresses','governance_addresses','staking_addresses']:
                if protocol.get(cat):
                    pretty = cat.replace('_',' ').replace('addresses','').strip()
                    print(f"   {pretty.title()}: {', '.join(protocol.get(cat)[:5])}{'...' if len(protocol.get(cat))>5 else ''}")
            print()

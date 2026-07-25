import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any
from security_analyzer import SecurityAnalyzer
from rugpull_detector import RugpullDetector

class SecurityOrchestrator:
    """
    Master orchestrator that coordinates security analysis and rugpull detection.
    Reads liquid_staking_analysis.json, performs comprehensive security analysis,
    and generates exportable reports.
    """
    
    def __init__(self, input_file: str = "liquid_staking_analysis.json"):
        self.input_file = input_file
        self.analyzer = SecurityAnalyzer()
        self.detector = RugpullDetector()
        self.protocols_data = []
        self.security_reports = []
        self.rugpull_reports = []
        
    def load_protocol_data(self) -> bool:
        """Load liquid staking analysis data from JSON"""
        try:
            with open(self.input_file, 'r') as f:
                data = json.load(f)
                self.protocols_data = data.get('protocols', [])
                print(f"✅ Loaded {len(self.protocols_data)} protocols from {self.input_file}")
                return True
        except FileNotFoundError:
            print(f"❌ Error: {self.input_file} not found")
            return False
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in {self.input_file}")
            return False
    
    def analyze_all_protocols(self) -> None:
        """Run security analysis on all loaded protocols"""
        print(f"\n🔍 Starting security analysis on {len(self.protocols_data)} protocols...\n")
        
        for idx, protocol in enumerate(self.protocols_data, 1):
            protocol_name = protocol.get('protocol', 'Unknown')
            contracts_str = str(protocol.get('contracts', {}))
            
            print(f"[{idx}/{len(self.protocols_data)}] Analyzing: {protocol_name}...", end=" ", flush=True)
            
            try:
                # Run security analysis
                analysis = self.analyzer.analyze_protocol(protocol_name, contracts_str)
                self.security_reports.append(analysis)
                
                # Run rugpull detection
                rugpull_report = self.detector.generate_rugpull_score(analysis)
                self.rugpull_reports.append(rugpull_report)
                
                print("✅")
            except Exception as e:
                print(f"❌ Error: {str(e)}")
    
    def rank_by_risk(self) -> List[Dict[str, Any]]:
        """Sort protocols by investment score (highest risk first)"""
        return sorted(self.rugpull_reports, 
                     key=lambda x: x['rugpull_score'], 
                     reverse=True)
    
    def filter_critical_protocols(self) -> List[Dict[str, Any]]:
        """Get protocols with CRITICAL rugpull risk"""
        return [p for p in self.rugpull_reports if p['risk_level'] == 'CRITICAL']
    
    def filter_high_risk_protocols(self) -> List[Dict[str, Any]]:
        """Get protocols with HIGH rugpull risk"""
        return [p for p in self.rugpull_reports if p['risk_level'] == 'HIGH']
    
    def export_to_json(self, output_file: str = "security_analysis_report.json") -> None:
        """Export comprehensive security analysis to JSON"""
        
        # Combine all data
        export_data = {
            "metadata": {
                "title": "🔒 DeFi Protocol Security & Rugpull Analysis Report",
                "description": "Comprehensive security analysis of liquid staking protocols",
                "generated_at": datetime.now().isoformat(),
                "total_protocols_analyzed": len(self.security_reports),
                "critical_risk_count": len(self.filter_critical_protocols()),
                "high_risk_count": len(self.filter_high_risk_protocols()),
            },
            "risk_summary": {
                "critical": self.filter_critical_protocols(),
                "high": self.filter_high_risk_protocols(),
                "all_ranked": self.rank_by_risk()
            },
            "detailed_analysis": self.security_reports,
            "rugpull_scores": self.rugpull_reports
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"✅ Exported to {output_file}")
    
    def export_to_csv(self, output_file: str = "security_analysis_report.csv") -> None:
        """Export security analysis summary to CSV"""
        
        if not self.rugpull_reports:
            print("No data to export")
            return
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = [
                'Protocol',
                'Risk Level',
                'Rugpull Score',
                'Investment Score',
                'Reward Contracts',
                'Treasury Contracts',
                'Fee Contracts',
                'Staking Contracts',
                'Bridge Contracts',
                'Centralized Control',
                'Withdrawal Restrictions',
                'Recommendation'
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for report in self.rank_by_risk():
                protocol_name = report['protocol']
                
                # Find corresponding security report
                security_report = next(
                    (r for r in self.security_reports if r['protocol'] == protocol_name),
                    None
                )
                
                if security_report:
                    writer.writerow({
                        'Protocol': protocol_name,
                        'Risk Level': report['risk_level'],
                        'Rugpull Score': f"{report['rugpull_score']:.1f}",
                        'Investment Score': f"{report['investment_score']:.1f}",
                        'Reward Contracts': len(security_report['reward_distribution']['addresses']),
                        'Treasury Contracts': len(security_report['treasury_multisig']['addresses']),
                        'Fee Contracts': len(security_report['fee_collection']['addresses']),
                        'Staking Contracts': len(security_report['staking_pool']['addresses']),
                        'Bridge Contracts': len(security_report['bridge_contracts']['addresses']),
                        'Centralized Control': 'Yes' if security_report['treasury_multisig']['centralized'] else 'No',
                        'Withdrawal Restrictions': 'Yes' if security_report['staking_pool']['has_restrictions'] else 'No',
                        'Recommendation': report['recommendation']
                    })
        
        print(f"✅ Exported to {output_file}")
    
    def export_risk_rankings(self, output_file: str = "risk_rankings.json") -> None:
        """Export risk rankings for easy reference"""
        
        rankings = {
            "generated_at": datetime.now().isoformat(),
            "ranking_criteria": "Investment Score (0-100, higher = more risky)",
            "protocols": []
        }
        
        for idx, report in enumerate(self.rank_by_risk(), 1):
            rankings['protocols'].append({
                "rank": idx,
                "protocol": report['protocol'],
                "risk_level": report['risk_level'],
                "rugpull_score": report['rugpull_score'],
                "investment_score": report['investment_score'],
                "recommendation": report['recommendation']
            })
        
        with open(output_file, 'w') as f:
            json.dump(rankings, f, indent=2)
        
        print(f"✅ Exported risk rankings to {output_file}")
    
    def export_detailed_protocol_reports(self, output_dir: str = "protocol_reports") -> None:
        """Export individual detailed reports for each protocol"""
        
        os.makedirs(output_dir, exist_ok=True)
        
        for report in self.security_reports:
            protocol_name = report['protocol']
            filename = os.path.join(output_dir, f"{protocol_name}_security_report.json")
            
            # Find corresponding rugpull report
            rugpull_report = next(
                (r for r in self.rugpull_reports if r['protocol'] == protocol_name),
                None
            )
            
            detailed_report = {
                "protocol": protocol_name,
                "generated_at": datetime.now().isoformat(),
                "security_analysis": report,
                "rugpull_assessment": rugpull_report
            }
            
            with open(filename, 'w') as f:
                json.dump(detailed_report, f, indent=2)
        
        print(f"✅ Exported {len(self.security_reports)} individual protocol reports to {output_dir}/")
    
    def print_summary_report(self) -> None:
        """Print summary report to console"""
        
        print("\n" + "="*80)
        print("🔒 DeFi PROTOCOL SECURITY & RUGPULL ANALYSIS SUMMARY")
        print("="*80)
        
        print(f"\n📊 Analysis Overview:")
        print(f"   Total Protocols Analyzed: {len(self.rugpull_reports)}")
        print(f"   Critical Risk: {len(self.filter_critical_protocols())}")
        print(f"   High Risk: {len(self.filter_high_risk_protocols())}")
        
        print(f"\n🚨 CRITICAL RISK PROTOCOLS (DO NOT INVEST):")
        critical = self.filter_critical_protocols()
        if critical:
            for idx, protocol in enumerate(critical, 1):
                print(f"   {idx}. {protocol['protocol']} - Score: {protocol['rugpull_score']:.1f}")
                print(f"      {protocol['recommendation']}")
        else:
            print("   ✅ None detected")
        
        print(f"\n⚠️  HIGH RISK PROTOCOLS (AVOID):")
        high_risk = self.filter_high_risk_protocols()
        if high_risk:
            for idx, protocol in enumerate(high_risk[:10], 1):  # Show top 10
                print(f"   {idx}. {protocol['protocol']} - Score: {protocol['rugpull_score']:.1f}")
        else:
            print("   ✅ None detected")
        
        print(f"\n📈 TOP 10 PROTOCOLS BY RISK SCORE:")
        ranked = self.rank_by_risk()
        for idx, protocol in enumerate(ranked[:10], 1):
            risk_icon = "🚨" if protocol['risk_level'] == 'CRITICAL' else "⚠️" if protocol['risk_level'] == 'HIGH' else "✅"
            print(f"   {idx}. {risk_icon} {protocol['protocol']}")
            print(f"      Risk: {protocol['risk_level']} | Score: {protocol['rugpull_score']:.1f}")
        
        print("\n" + "="*80)
    
    def run_full_analysis(self) -> bool:
        """Execute complete security analysis pipeline"""
        
        print("\n" + "="*80)
        print("🔒 STARTING LADY PRIME - DeFi SECURITY ANALYSIS ENGINE")
        print("="*80)
        
        # Step 1: Load data
        if not self.load_protocol_data():
            return False
        
        # Step 2: Analyze all protocols
        self.analyze_all_protocols()
        
        # Step 3: Print summary
        self.print_summary_report()
        
        # Step 4: Export reports
        print(f"\n📁 Exporting reports...")
        self.export_to_json("security_analysis_report.json")
        self.export_to_csv("security_analysis_report.csv")
        self.export_risk_rankings("risk_rankings.json")
        self.export_detailed_protocol_reports("protocol_reports")
        
        print("\n✅ Security analysis complete!")
        print("="*80)
        
        return True


def main():
    """Main entry point"""
    orchestrator = SecurityOrchestrator("liquid_staking_analysis.json")
    orchestrator.run_full_analysis()


if __name__ == "__main__":
    main()

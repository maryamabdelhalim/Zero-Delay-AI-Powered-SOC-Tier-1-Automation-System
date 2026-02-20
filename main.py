#!/usr/bin/env python3
"""
SOC Tier 1 Automation System - Main Entry Point
Complete incident response automation in 5 phases
"""

import sys
import os
import argparse
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cli.interface import SOCInterface
from llm_engine import LLMEngine
from phases.phase1_identification import IncidentIdentification
from phases.phase2_containment import IncidentContainment
from phases.phase3_analysis import IncidentAnalysis
from phases.phase4_eradication import IncidentEradication
from phases.phase5_recovery import IncidentRecovery
from simulation.mock_data import AttackSimulator


class SOCAutomation:
    """Main SOC Automation System Orchestrator"""
    
    def __init__(self, use_llm: bool = True):
        """Initialize SOC Automation System"""
        self.interface = SOCInterface()
        self.use_llm = use_llm
        
        # Initialize LLM Engine if available
        if use_llm:
            try:
                self.llm_engine = LLMEngine()
                if not self.llm_engine.health_check():
                    self.interface.show_warning(
                        "LLM Engine not available. Running in basic mode.\n"
                        "Install Ollama and run: ollama pull llama3.2"
                    )
                    self.llm_engine = None
            except Exception as e:
                self.interface.show_warning(f"LLM Engine error: {e}. Running in basic mode.")
                self.llm_engine = None
        else:
            self.llm_engine = None
        
        # Initialize phases
        self.phase1 = IncidentIdentification(self.llm_engine)
        self.phase2 = IncidentContainment(self.llm_engine)
        self.phase3 = IncidentAnalysis(self.llm_engine)
        self.phase4 = IncidentEradication(self.llm_engine)
        self.phase5 = IncidentRecovery(self.llm_engine)
        
        # Initialize simulator
        self.simulator = AttackSimulator()
    
    def run_full_incident_response(
        self, 
        log_data: str, 
        attack_type: str = None,
        auto_execute: bool = False
    ) -> dict:
        """
        Run complete 5-phase incident response
        
        Args:
            log_data: Security log data
            attack_type: Known attack type (optional)
            auto_execute: Auto-execute containment actions
            
        Returns:
            Complete incident report
        """
        try:
            # Phase 1: Identification
            self.interface.show_phase_progress(1, "IDENTIFICATION", "running")
            self.interface.show_progress_spinner("Analyzing logs and identifying threats...", 2.0)
            
            phase1_results = self.phase1.identify(log_data)
            
            if not phase1_results.get('confirmed'):
                self.interface.show_error("No confirmed incident detected.")
                return {'success': False, 'reason': 'No incident detected'}
            
            self.interface.show_phase_progress(1, "IDENTIFICATION", "complete")
            self.interface.show_incident_summary(phase1_results)
            self.interface.show_recommendations(phase1_results.get('recommendations', []))
            
            # Confirm before proceeding
            if not auto_execute:
                if not self.interface.ask_confirmation("\n🔸 Proceed to Containment?"):
                    self.interface.show_info("Incident response paused by user.")
                    return {'success': False, 'reason': 'User paused'}
            
            self.interface.show_divider()
            
            # Phase 2: Containment
            self.interface.show_phase_progress(2, "CONTAINMENT", "running")
            self.interface.show_progress_spinner("Implementing containment measures...", 2.0)
            
            phase2_results = self.phase2.contain(phase1_results, auto_execute=False)
            
            self.interface.show_phase_progress(2, "CONTAINMENT", "complete")
            self.interface.show_containment_actions(phase2_results.get('actions', []))
            
            if not auto_execute:
                if not self.interface.ask_confirmation("\n🔸 Proceed to Analysis?"):
                    self.interface.show_info("Incident response paused by user.")
                    return {'success': False, 'reason': 'User paused'}
            
            self.interface.show_divider()
            
            # Phase 3: Analysis
            self.interface.show_phase_progress(3, "ANALYSIS", "running")
            self.interface.show_progress_spinner("Performing deep analysis...", 2.0)
            
            phase3_results = self.phase3.analyze(
                phase1_results,
                phase2_results,
                log_data
            )
            
            self.interface.show_phase_progress(3, "ANALYSIS", "complete")
            self.interface.show_analysis_results(phase3_results)
            
            if not auto_execute:
                if not self.interface.ask_confirmation("\n🔸 Proceed to Eradication?"):
                    self.interface.show_info("Incident response paused by user.")
                    return {'success': False, 'reason': 'User paused'}
            
            self.interface.show_divider()
            
            # Phase 4: Eradication
            self.interface.show_phase_progress(4, "ERADICATION", "running")
            self.interface.show_progress_spinner("Eliminating root cause...", 2.0)
            
            phase4_results = self.phase4.eradicate(
                phase1_results,
                phase3_results
            )
            
            self.interface.show_phase_progress(4, "ERADICATION", "complete")
            self.interface.show_eradication_summary(phase4_results)
            
            if not auto_execute:
                if not self.interface.ask_confirmation("\n🔸 Proceed to Recovery?"):
                    self.interface.show_info("Incident response paused by user.")
                    return {'success': False, 'reason': 'User paused'}
            
            self.interface.show_divider()
            
            # Phase 5: Recovery
            self.interface.show_phase_progress(5, "RECOVERY", "running")
            self.interface.show_progress_spinner("Restoring services...", 2.0)
            
            phase5_results = self.phase5.recover(
                phase1_results,
                phase4_results
            )
            
            self.interface.show_phase_progress(5, "RECOVERY", "complete")
            self.interface.show_recovery_plan(phase5_results)
            
            # Final status
            self.interface.show_divider()
            self.interface.show_final_status(success=True)
            
            # Compile complete report
            complete_report = {
                'success': True,
                'incident_id': phase1_results.get('incident_id'),
                'timestamp': datetime.now().isoformat(),
                'phase1_identification': phase1_results,
                'phase2_containment': phase2_results,
                'phase3_analysis': phase3_results,
                'phase4_eradication': phase4_results,
                'phase5_recovery': phase5_results
            }
            
            return complete_report
            
        except Exception as e:
            self.interface.show_error(f"Incident response failed: {str(e)}")
            self.interface.show_final_status(success=False)
            return {'success': False, 'error': str(e)}
    
    def simulate_attack(self, attack_type: str = None):
        """Simulate an attack and run full response"""
        self.interface.clear_screen()
        self.interface.show_banner()
        
        if attack_type is None:
            self.interface.show_attack_types_menu()
            choice = self.interface.get_input("Select attack type", "7")
            
            attack_map = {
                '1': 'ddos',
                '2': 'dos',
                '3': 'brute_force',
                '4': 'sql_injection',
                '5': 'xss',
                '6': 'port_scan',
                '7': None
            }
            attack_type = attack_map.get(choice)
        
        self.interface.show_info(f"Generating simulated attack: {attack_type or 'Random'}...")
        
        # Generate attack
        attack_data = self.simulator.generate_attack(attack_type)
        
        self.interface.show_success(f"Attack simulated: {attack_data['attack_type'].upper()}")
        
        # Show sample logs
        self.interface.console.print("\n📋 Sample Attack Logs:")
        self.interface.console.print(
            attack_data['logs'][:500] + "\n...\n",
            style="dim"
        )
        
        # Ask to proceed
        if not self.interface.ask_confirmation("\n🔸 Start incident response?"):
            self.interface.show_info("Simulation cancelled.")
            return
        
        self.interface.show_divider()
        
        # Run full response
        report = self.run_full_incident_response(
            log_data=attack_data['logs'],
            attack_type=attack_data['attack_type'],
            auto_execute=False
        )
        
        if report.get('success'):
            self.interface.show_info(
                f"Complete report saved: {report.get('incident_id')}"
            )
    
    def analyze_log_file(self, file_path: str):
        """Analyze a log file"""
        self.interface.clear_screen()
        self.interface.show_banner()
        
        try:
            with open(file_path, 'r') as f:
                log_data = f.read()
            
            self.interface.show_success(f"Loaded log file: {file_path}")
            self.interface.show_info(f"Log size: {len(log_data)} characters")
            
            if not self.interface.ask_confirmation("\n🔸 Start analysis?"):
                return
            
            self.interface.show_divider()
            
            # Run full response
            report = self.run_full_incident_response(
                log_data=log_data,
                auto_execute=False
            )
            
            if report.get('success'):
                self.interface.show_info(
                    f"Analysis complete: {report.get('incident_id')}"
                )
                
        except FileNotFoundError:
            self.interface.show_error(f"File not found: {file_path}")
        except Exception as e:
            self.interface.show_error(f"Error reading file: {str(e)}")
    
    def interactive_mode(self):
        """Run in interactive mode with menu"""
        while True:
            self.interface.clear_screen()
            self.interface.show_banner()
            self.interface.show_main_menu()
            
            choice = self.interface.get_input("Select option", "1")
            
            if choice == '1':
                self.simulate_attack()
            elif choice == '2':
                file_path = self.interface.get_input("Enter log file path")
                self.analyze_log_file(file_path)
            elif choice == '3':
                self.interface.show_info("Report viewing feature coming soon!")
                self.interface.wait_for_enter()
            elif choice == '4':
                self.interface.show_info("Configuration feature coming soon!")
                self.interface.wait_for_enter()
            elif choice == '5':
                self.show_help()
                self.interface.wait_for_enter()
            elif choice == '6':
                self.interface.show_info("Goodbye! Stay secure! 🛡️")
                break
            else:
                self.interface.show_error("Invalid option!")
                self.interface.wait_for_enter()
    
    def show_help(self):
        """Show help information"""
        help_text = """
╔═══════════════════════════════════════════════════════════════╗
║                      📖 HELP & DOCUMENTATION                  ║
╚═══════════════════════════════════════════════════════════════╝

🎯 USAGE:
  python main.py                          # Interactive mode
  python main.py simulate --attack ddos   # Simulate DDoS attack
  python main.py analyze --file logs.txt  # Analyze log file
  python main.py --help                   # Show this help

📋 THE 5 PHASES:
  1️⃣  IDENTIFICATION   - Detect and classify incidents
  2️⃣  CONTAINMENT      - Stop attack propagation
  3️⃣  ANALYSIS         - Deep investigation
  4️⃣  ERADICATION      - Eliminate root cause
  5️⃣  RECOVERY         - Restore normal operations

🔧 REQUIREMENTS:
  • Python 3.9+
  • Ollama (optional, for LLM features)
  • Dependencies: pip install -r requirements.txt

📚 DOCUMENTATION:
  • README.md - Full documentation
  • config/config.yaml - Configuration options

💡 TIPS:
  • Start with simulated attacks to learn the system
  • Review generated reports for insights
  • Adjust config.yaml for your environment

🆘 SUPPORT:
  • GitHub: [repository URL]
  • Documentation: [docs URL]
"""
        self.interface.console.print(help_text, style="cyan")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SOC Tier 1 Automation System',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Simulate command
    simulate_parser = subparsers.add_parser('simulate', help='Simulate an attack')
    simulate_parser.add_argument(
        '--attack-type',
        choices=['ddos', 'dos', 'brute_force', 'sql_injection', 'xss', 'port_scan'],
        help='Type of attack to simulate'
    )
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a log file')
    analyze_parser.add_argument(
        '--log-file',
        required=True,
        help='Path to log file'
    )
    
    # Interactive command
    subparsers.add_parser('interactive', help='Run in interactive mode')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize system
    soc = SOCAutomation(use_llm=True)
    
    # Execute command
    if args.command == 'simulate':
        soc.simulate_attack(args.attack_type)
    elif args.command == 'analyze':
        soc.analyze_log_file(args.log_file)
    elif args.command == 'interactive' or args.command is None:
        soc.interactive_mode()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

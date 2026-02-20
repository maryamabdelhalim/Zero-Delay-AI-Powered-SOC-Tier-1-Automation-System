"""
CLI Interface - Beautiful command-line interface using Rich
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import box
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
import time
from datetime import datetime

console = Console()


class SOCInterface:
    """Beautiful CLI interface for SOC Automation"""
    
    def __init__(self):
        self.console = console
        
    def show_banner(self):
        """Display welcome banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🛡️  SOC TIER 1 AUTOMATION SYSTEM  🛡️                     ║
║                                                               ║
║           Powered by AI | Built for Security                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
        self.console.print(banner, style="bold cyan")
        self.console.print(f"⏰ System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim")
        self.console.print()
    
    def show_main_menu(self):
        """Display main menu"""
        menu_table = Table(title="🎯 Main Menu", box=box.ROUNDED, show_header=False)
        menu_table.add_column("Option", style="cyan", width=10)
        menu_table.add_column("Description", style="white")
        
        options = [
            ("1", "🎭 Simulate Attack (Demo Mode)"),
            ("2", "📁 Analyze Log File"),
            ("3", "📊 View Reports"),
            ("4", "🔧 System Configuration"),
            ("5", "❓ Help & Documentation"),
            ("6", "🚪 Exit")
        ]
        
        for opt, desc in options:
            menu_table.add_row(opt, desc)
        
        self.console.print(menu_table)
        self.console.print()
    
    def show_attack_types_menu(self):
        """Display attack types menu"""
        attack_table = Table(title="🎭 Select Attack Type", box=box.ROUNDED, show_header=False)
        attack_table.add_column("Option", style="cyan", width=10)
        attack_table.add_column("Attack Type", style="yellow")
        attack_table.add_column("Description", style="dim")
        
        attacks = [
            ("1", "DDoS", "Distributed Denial of Service"),
            ("2", "DoS", "Denial of Service"),
            ("3", "Brute Force", "Password Cracking Attack"),
            ("4", "SQL Injection", "Database Injection"),
            ("5", "XSS", "Cross-Site Scripting"),
            ("6", "Port Scan", "Network Reconnaissance"),
            ("7", "Random", "Surprise me!")
        ]
        
        for opt, name, desc in attacks:
            attack_table.add_row(opt, name, desc)
        
        self.console.print(attack_table)
        self.console.print()
    
    def show_phase_progress(self, phase_num: int, phase_name: str, status: str = "running"):
        """Show phase progress"""
        status_emoji = {
            "running": "⏳",
            "complete": "✅",
            "error": "❌",
            "pending": "⏸️"
        }
        
        emoji = status_emoji.get(status, "❓")
        
        phase_text = f"{emoji} Phase {phase_num}: {phase_name}"
        
        if status == "running":
            self.console.print(f"\n{phase_text}", style="bold yellow")
        elif status == "complete":
            self.console.print(f"\n{phase_text}", style="bold green")
        elif status == "error":
            self.console.print(f"\n{phase_text}", style="bold red")
    
    def show_incident_summary(self, incident_data: dict):
        """Display incident summary"""
        summary_table = Table(title="🚨 Incident Summary", box=box.DOUBLE_EDGE, show_header=False)
        summary_table.add_column("Field", style="cyan bold", width=25)
        summary_table.add_column("Value", style="white")
        
        data = [
            ("Incident ID", incident_data.get('incident_id', 'N/A')),
            ("Attack Type", incident_data.get('attack_type', 'N/A')),
            ("Severity", self._colorize_severity(incident_data.get('severity', 'UNKNOWN'))),
            ("Confidence", f"{incident_data.get('confidence', 0) * 100:.0f}%"),
            ("Source IPs", str(len(incident_data.get('source_ips', [])))),
            ("Affected Assets", str(len(incident_data.get('affected_assets', [])))),
            ("Timestamp", incident_data.get('timestamp', 'N/A'))
        ]
        
        for field, value in data:
            summary_table.add_row(field, str(value))
        
        self.console.print(summary_table)
        self.console.print()
    
    def _colorize_severity(self, severity: str) -> Text:
        """Colorize severity level"""
        colors = {
            'CRITICAL': 'bold red',
            'HIGH': 'bold yellow',
            'MEDIUM': 'bold blue',
            'LOW': 'bold green'
        }
        return Text(severity, style=colors.get(severity, 'white'))
    
    def show_recommendations(self, recommendations: list):
        """Display recommendations"""
        if not recommendations:
            return
        
        rec_panel = Panel(
            "\n".join([f"• {rec}" for rec in recommendations[:5]]),
            title="💡 Immediate Recommendations",
            border_style="yellow"
        )
        self.console.print(rec_panel)
        self.console.print()
    
    def show_containment_actions(self, actions: list):
        """Display containment actions"""
        action_table = Table(title="🛡️  Containment Actions", box=box.ROUNDED)
        action_table.add_column("ID", style="cyan")
        action_table.add_column("Type", style="yellow")
        action_table.add_column("Description", style="white")
        action_table.add_column("Priority", style="magenta")
        
        for action in actions[:5]:
            action_table.add_row(
                action.get('action_id', 'N/A'),
                action.get('type', 'N/A'),
                action.get('description', 'N/A')[:50] + "...",
                action.get('priority', 'N/A')
            )
        
        self.console.print(action_table)
        self.console.print()
    
    def show_analysis_results(self, analysis: dict):
        """Display analysis results"""
        # Attack Vector
        av = analysis.get('attack_vector', {})
        vector_text = f"""
🎯 Attack Vector: {av.get('attack_type', 'Unknown')}
📊 Sophistication: {av.get('sophistication', 'Unknown')}
🚪 Entry Points: {', '.join(av.get('entry_points', ['Unknown']))}
"""
        self.console.print(Panel(vector_text.strip(), title="Attack Vector Analysis", border_style="blue"))
        
        # Impact
        impact = analysis.get('impact_assessment', {})
        impact_text = f"""
⚠️  Severity: {impact.get('severity', 'Unknown')}
💥 Service Disruption: {impact.get('service_disruption', 'Unknown')}
💰 Financial Impact: {impact.get('financial_impact', 'Unknown')}
"""
        self.console.print(Panel(impact_text.strip(), title="Impact Assessment", border_style="red"))
        self.console.print()
    
    def show_eradication_summary(self, eradication: dict):
        """Display eradication summary"""
        summary_text = f"""
✅ Vulnerabilities Fixed: {len(eradication.get('vulnerabilities', []))}
🔧 Patches Applied: {len(eradication.get('patches', []))}
🛡️  Hardening Steps: {len(eradication.get('hardening_steps', []))}
⚖️  Permanent Rules: {len(eradication.get('permanent_rules', []))}
"""
        self.console.print(Panel(summary_text.strip(), title="🔧 Eradication Summary", border_style="green"))
        self.console.print()
    
    def show_recovery_plan(self, recovery: dict):
        """Display recovery plan"""
        plan = recovery.get('recovery_plan', {})
        plan_text = f"""
📋 Strategy: {plan.get('strategy', 'Unknown')}
⏳ Duration: {plan.get('total_duration', 'Unknown')}
⚠️  Risk: {plan.get('risk_assessment', 'Unknown')}
🔄 Phases: {len(plan.get('phases', []))}
"""
        self.console.print(Panel(plan_text.strip(), title="🔄 Recovery Plan", border_style="cyan"))
        self.console.print()
    
    def show_final_status(self, success: bool = True):
        """Display final status"""
        if success:
            status_text = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║               ✅ INCIDENT SUCCESSFULLY RESOLVED ✅            ║
║                                                               ║
║          All 5 phases completed successfully!                ║
║          System returned to normal operation.                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
            self.console.print(status_text, style="bold green")
        else:
            status_text = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║                 ❌ INCIDENT RESOLUTION FAILED ❌              ║
║                                                               ║
║            Please review logs and retry.                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
            self.console.print(status_text, style="bold red")
    
    def show_progress_spinner(self, message: str, duration: float = 2.0):
        """Show progress spinner"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(message, total=None)
            time.sleep(duration)
    
    def ask_confirmation(self, message: str) -> bool:
        """Ask for user confirmation"""
        return Confirm.ask(message)
    
    def get_input(self, prompt_text: str, default: str = None) -> str:
        """Get user input"""
        return Prompt.ask(prompt_text, default=default)
    
    def show_error(self, message: str):
        """Display error message"""
        self.console.print(f"\n❌ Error: {message}", style="bold red")
        self.console.print()
    
    def show_success(self, message: str):
        """Display success message"""
        self.console.print(f"\n✅ {message}", style="bold green")
        self.console.print()
    
    def show_info(self, message: str):
        """Display info message"""
        self.console.print(f"\nℹ️  {message}", style="bold blue")
        self.console.print()
    
    def show_warning(self, message: str):
        """Display warning message"""
        self.console.print(f"\n⚠️  {message}", style="bold yellow")
        self.console.print()
    
    def show_divider(self):
        """Show divider line"""
        self.console.print("─" * 60, style="dim")
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def wait_for_enter(self):
        """Wait for user to press Enter"""
        self.console.print("\nPress [bold cyan]Enter[/bold cyan] to continue...", end="")
        input()


# Example usage
if __name__ == "__main__":
    interface = SOCInterface()
    
    # Demo
    interface.clear_screen()
    interface.show_banner()
    interface.show_main_menu()
    
    # Simulate incident display
    sample_incident = {
        'incident_id': 'INC-20260128-103045',
        'attack_type': 'DDOS',
        'severity': 'CRITICAL',
        'confidence': 0.95,
        'source_ips': ['45.67.89.123', '103.45.67.89'],
        'affected_assets': ['web-server-01'],
        'timestamp': datetime.now().isoformat()
    }
    
    interface.show_incident_summary(sample_incident)
    interface.show_recommendations([
        "Enable rate limiting immediately",
        "Block malicious IPs",
        "Escalate to SOC Tier 2"
    ])

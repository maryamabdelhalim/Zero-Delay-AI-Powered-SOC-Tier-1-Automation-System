"""
Phase 2: Containment - الاحتواء
Stop attack propagation and minimize impact
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json


class IncidentContainment:
    """
    المرحلة الثانية: احتواء الهجوم
    Phase 2: Incident Containment
    """
    
    # Containment strategies by attack type
    CONTAINMENT_STRATEGIES = {
        'DDOS': [
            'rate_limiting',
            'ip_blocking',
            'geo_blocking',
            'cdn_activation',
            'load_balancing'
        ],
        'DOS': [
            'resource_throttling',
            'ip_blocking',
            'service_isolation'
        ],
        'BRUTE_FORCE': [
            'account_lockout',
            'ip_blocking',
            'captcha_activation',
            'mfa_enforcement'
        ],
        'SQL_INJECTION': [
            'waf_rules',
            'database_isolation',
            'query_filtering',
            'connection_limiting'
        ],
        'XSS': [
            'waf_rules',
            'input_sanitization',
            'content_filtering'
        ],
        'PORT_SCAN': [
            'ip_blocking',
            'port_filtering',
            'ids_alert'
        ],
        'MALWARE': [
            'system_isolation',
            'network_segmentation',
            'process_termination'
        ]
    }
    
    def __init__(self, llm_engine=None):
        """Initialize Containment module"""
        self.llm_engine = llm_engine
        
    def contain(
        self, 
        incident_data: Dict[str, Any],
        auto_execute: bool = False
    ) -> Dict[str, Any]:
        """
        Main containment function
        
        Args:
            incident_data: Results from Phase 1
            auto_execute: Whether to auto-execute containment actions
            
        Returns:
            Containment results
        """
        print("\n" + "="*60)
        print("🛡️  Phase 2: CONTAINMENT")
        print("="*60)
        
        attack_type = incident_data.get('attack_type', 'UNKNOWN')
        severity = incident_data.get('severity', 'LOW')
        source_ips = incident_data.get('source_ips', [])
        affected_assets = incident_data.get('affected_assets', [])
        
        # Step 1: Determine containment strategy
        strategy = self._select_strategy(attack_type, severity)
        
        # Step 2: Generate containment actions
        actions = self._generate_actions(
            attack_type, 
            source_ips, 
            affected_assets,
            severity
        )
        
        # Step 3: Generate firewall rules
        firewall_rules = self._generate_firewall_rules(source_ips, attack_type)
        
        # Step 4: Rate limiting configuration
        rate_limits = self._generate_rate_limits(attack_type, severity)
        
        # Step 5: WAF rules (if applicable)
        waf_rules = self._generate_waf_rules(attack_type)
        
        # Step 6: LLM-based recommendations
        if self.llm_engine:
            llm_recommendations = self._llm_recommendations(
                incident_data, 
                actions
            )
        else:
            llm_recommendations = None
        
        # Step 7: Execute actions (if auto_execute)
        execution_status = "SIMULATED"
        if auto_execute:
            execution_status = self._execute_actions(actions)
        
        # Compile results
        results = {
            'phase': 'CONTAINMENT',
            'timestamp': datetime.now().isoformat(),
            'incident_id': incident_data.get('incident_id'),
            'strategy': strategy,
            'actions': actions,
            'firewall_rules': firewall_rules,
            'rate_limits': rate_limits,
            'waf_rules': waf_rules,
            'blocked_ips': source_ips,
            'blocked_count': len(source_ips),
            'execution_status': execution_status,
            'llm_recommendations': llm_recommendations,
            'success': True
        }
        
        self._print_results(results)
        
        return results
    
    def _select_strategy(self, attack_type: str, severity: str) -> List[str]:
        """Select appropriate containment strategy"""
        base_strategy = self.CONTAINMENT_STRATEGIES.get(
            attack_type, 
            ['ip_blocking', 'monitoring']
        )
        
        # Add aggressive measures for critical severity
        if severity == "CRITICAL":
            base_strategy = ['immediate_isolation'] + base_strategy
        
        return base_strategy
    
    def _generate_actions(
        self,
        attack_type: str,
        source_ips: List[str],
        affected_assets: List[str],
        severity: str
    ) -> List[Dict[str, Any]]:
        """Generate specific containment actions"""
        actions = []
        
        # Action 1: IP Blocking
        if source_ips:
            actions.append({
                'action_id': 'ACT-001',
                'type': 'IP_BLOCKING',
                'priority': 'HIGH',
                'description': f'Block {len(source_ips)} malicious IP addresses',
                'targets': source_ips[:10],  # Limit to first 10 for display
                'command': self._generate_block_command(source_ips),
                'reversible': True,
                'estimated_time': '< 1 minute'
            })
        
        # Action 2: Rate Limiting
        if attack_type in ['DDOS', 'DOS', 'BRUTE_FORCE']:
            actions.append({
                'action_id': 'ACT-002',
                'type': 'RATE_LIMITING',
                'priority': 'HIGH',
                'description': 'Enable aggressive rate limiting',
                'targets': affected_assets,
                'parameters': {
                    'requests_per_minute': 100 if severity == 'CRITICAL' else 500,
                    'concurrent_connections': 50
                },
                'reversible': True,
                'estimated_time': '< 30 seconds'
            })
        
        # Action 3: WAF Activation
        if attack_type in ['SQL_INJECTION', 'XSS']:
            actions.append({
                'action_id': 'ACT-003',
                'type': 'WAF_RULES',
                'priority': 'HIGH',
                'description': 'Activate specialized WAF rules',
                'targets': affected_assets,
                'rules': self._generate_waf_rules(attack_type),
                'reversible': True,
                'estimated_time': '< 1 minute'
            })
        
        # Action 4: Service Isolation (for CRITICAL)
        if severity == 'CRITICAL':
            actions.append({
                'action_id': 'ACT-004',
                'type': 'SERVICE_ISOLATION',
                'priority': 'CRITICAL',
                'description': 'Isolate affected services from network',
                'targets': affected_assets,
                'reversible': True,
                'estimated_time': '2-5 minutes',
                'requires_approval': True
            })
        
        # Action 5: Monitoring Enhancement
        actions.append({
            'action_id': 'ACT-005',
            'type': 'MONITORING',
            'priority': 'MEDIUM',
            'description': 'Enhance monitoring for affected assets',
            'targets': affected_assets,
            'parameters': {
                'log_level': 'DEBUG',
                'alert_threshold': 'LOW',
                'sampling_rate': '100%'
            },
            'reversible': True,
            'estimated_time': '< 30 seconds'
        })
        
        return actions
    
    def _generate_firewall_rules(
        self, 
        ips: List[str], 
        attack_type: str
    ) -> Dict[str, List[str]]:
        """Generate firewall rules for different platforms"""
        if not ips:
            return {}
        
        rules = {
            'iptables': [],
            'pfsense': [],
            'cisco_asa': [],
            'palo_alto': []
        }
        
        # iptables rules
        for ip in ips[:20]:  # Limit to 20 IPs
            rules['iptables'].append(
                f"iptables -A INPUT -s {ip} -j DROP"
            )
        
        # pfSense rules
        for ip in ips[:20]:
            rules['pfsense'].append(
                f"block in quick from {ip} to any"
            )
        
        # Cisco ASA rules
        for ip in ips[:20]:
            rules['cisco_asa'].append(
                f"access-list BLOCK_MALICIOUS deny ip host {ip} any"
            )
        
        # Palo Alto rules
        rules['palo_alto'].append(
            f"# Create address group for malicious IPs"
        )
        for i, ip in enumerate(ips[:20], 1):
            rules['palo_alto'].append(
                f"set address malicious-ip-{i} ip-netmask {ip}"
            )
        
        return rules
    
    def _generate_block_command(self, ips: List[str]) -> str:
        """Generate quick block command"""
        if len(ips) == 1:
            return f"iptables -A INPUT -s {ips[0]} -j DROP"
        else:
            return f"# Block {len(ips)} IPs - see firewall_rules for details"
    
    def _generate_rate_limits(self, attack_type: str, severity: str) -> Dict[str, Any]:
        """Generate rate limiting configuration"""
        
        # Base limits
        limits = {
            'requests_per_second': 10,
            'requests_per_minute': 500,
            'concurrent_connections': 100,
            'burst_size': 20
        }
        
        # Adjust based on severity
        if severity == 'CRITICAL':
            limits = {
                'requests_per_second': 5,
                'requests_per_minute': 100,
                'concurrent_connections': 50,
                'burst_size': 10
            }
        elif severity == 'HIGH':
            limits = {
                'requests_per_second': 7,
                'requests_per_minute': 300,
                'concurrent_connections': 75,
                'burst_size': 15
            }
        
        # Attack-specific adjustments
        if attack_type == 'DDOS':
            limits['requests_per_second'] //= 2
            limits['concurrent_connections'] //= 2
        
        return limits
    
    def _generate_waf_rules(self, attack_type: str) -> List[Dict[str, Any]]:
        """Generate WAF rules for specific attack types"""
        rules = []
        
        if attack_type == 'SQL_INJECTION':
            rules.extend([
                {
                    'rule_id': 'WAF-SQL-001',
                    'description': 'Block SQL injection patterns',
                    'pattern': r"(\b(union|select|insert|update|delete|drop|create|alter)\b)",
                    'action': 'BLOCK',
                    'log': True
                },
                {
                    'rule_id': 'WAF-SQL-002',
                    'description': 'Block SQL comments',
                    'pattern': r"(--|/\*|\*/|#)",
                    'action': 'BLOCK',
                    'log': True
                }
            ])
        
        elif attack_type == 'XSS':
            rules.extend([
                {
                    'rule_id': 'WAF-XSS-001',
                    'description': 'Block script tags',
                    'pattern': r"<script[^>]*>.*?</script>",
                    'action': 'BLOCK',
                    'log': True
                },
                {
                    'rule_id': 'WAF-XSS-002',
                    'description': 'Block javascript: protocol',
                    'pattern': r"javascript:",
                    'action': 'BLOCK',
                    'log': True
                }
            ])
        
        return rules
    
    def _llm_recommendations(
        self, 
        incident_data: Dict, 
        actions: List[Dict]
    ) -> Optional[Dict]:
        """Get LLM-based containment recommendations"""
        try:
            prompt = f"""
Based on this security incident:
- Attack Type: {incident_data.get('attack_type')}
- Severity: {incident_data.get('severity')}
- Affected Assets: {', '.join(incident_data.get('affected_assets', [])[:5])}

Proposed containment actions:
{json.dumps(actions, indent=2)}

Provide:
1. Assessment of proposed actions
2. Additional recommendations
3. Potential risks of containment
4. Priority order for execution

Return as structured JSON.
"""
            response = self.llm_engine.generate_response(
                prompt,
                system_prompt="You are a SOC containment expert."
            )
            
            return {'recommendations': response}
        except Exception as e:
            return {'error': str(e)}
    
    def _execute_actions(self, actions: List[Dict]) -> str:
        """
        Execute containment actions (SIMULATION MODE)
        In production, this would integrate with real systems
        """
        # This is a simulation - in production, integrate with:
        # - Firewall APIs
        # - WAF APIs
        # - Network management systems
        # - SIEM platforms
        
        print("\n⚠️  SIMULATION MODE - Actions not executed on real systems")
        return "SIMULATED"
    
    def _print_results(self, results: Dict):
        """Pretty print containment results"""
        print(f"\n{'─'*60}")
        print(f"🆔 Incident ID: {results['incident_id']}")
        print(f"⏰ Timestamp: {results['timestamp']}")
        print(f"{'─'*60}")
        
        print(f"\n📋 Containment Strategy:")
        for strategy in results['strategy']:
            print(f"  • {strategy.replace('_', ' ').title()}")
        
        print(f"\n⚡ Actions Taken:")
        for action in results['actions']:
            priority_emoji = "🔴" if action['priority'] == 'CRITICAL' else "🟡" if action['priority'] == 'HIGH' else "🟢"
            print(f"  {priority_emoji} [{action['action_id']}] {action['description']}")
            print(f"     Time: {action['estimated_time']}")
        
        print(f"\n🚫 Blocked IPs: {results['blocked_count']}")
        for ip in results['blocked_ips'][:5]:
            print(f"  • {ip}")
        if results['blocked_count'] > 5:
            print(f"  ... and {results['blocked_count'] - 5} more")
        
        print(f"\n⚙️  Rate Limits Applied:")
        limits = results['rate_limits']
        print(f"  • Requests/sec: {limits['requests_per_second']}")
        print(f"  • Requests/min: {limits['requests_per_minute']}")
        print(f"  • Concurrent connections: {limits['concurrent_connections']}")
        
        if results.get('waf_rules'):
            print(f"\n🛡️  WAF Rules: {len(results['waf_rules'])} rules activated")
        
        print(f"\n📊 Execution Status: {results['execution_status']}")
        
        print(f"\n{'─'*60}")
        print("✓ Phase 2 Complete - Attack Contained")
        print("─"*60 + "\n")


# Example usage
if __name__ == "__main__":
    # Test with sample incident data
    sample_incident = {
        'incident_id': 'INC-20260128-103045',
        'attack_type': 'DDOS',
        'severity': 'CRITICAL',
        'source_ips': ['45.67.89.123', '103.45.67.89', '78.23.45.67'],
        'affected_assets': ['web-server-01', 'web-server-02']
    }
    
    container = IncidentContainment()
    results = container.contain(sample_incident, auto_execute=False)
    
    print("\n📋 Full Results:")
    print(json.dumps(results, indent=2, default=str))

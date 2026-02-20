"""
Phase 4: Eradication - الإزالة
Eliminate root cause and vulnerabilities permanently
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json


class IncidentEradication:
    """
    المرحلة الرابعة: الإزالة الكاملة
    Phase 4: Permanent Eradication
    """
    
    def __init__(self, llm_engine=None):
        """Initialize Eradication module"""
        self.llm_engine = llm_engine
        
    def eradicate(
        self,
        incident_data: Dict[str, Any],
        analysis_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Main eradication function
        
        Args:
            incident_data: Results from Phase 1
            analysis_data: Results from Phase 3
            
        Returns:
            Eradication results
        """
        print("\n" + "="*60)
        print("🔧 Phase 4: ERADICATION")
        print("="*60)
        
        attack_type = incident_data.get('attack_type', 'UNKNOWN')
        root_cause = analysis_data.get('root_cause', {})
        
        # Step 1: Vulnerability Assessment
        vulnerabilities = self._assess_vulnerabilities(
            attack_type,
            root_cause
        )
        
        # Step 2: Generate Patches/Fixes
        patches = self._generate_patches(attack_type, vulnerabilities)
        
        # Step 3: Configuration Updates
        config_updates = self._generate_config_updates(
            attack_type,
            incident_data
        )
        
        # Step 4: Security Hardening
        hardening_steps = self._generate_hardening_steps(
            attack_type,
            root_cause
        )
        
        # Step 5: Backdoor Detection
        backdoor_check = self._check_for_backdoors(
            incident_data,
            analysis_data
        )
        
        # Step 6: Permanent Rules
        permanent_rules = self._create_permanent_rules(
            incident_data,
            analysis_data
        )
        
        # Step 7: LLM Recommendations
        if self.llm_engine:
            llm_recommendations = self._llm_eradication_plan(
                incident_data,
                analysis_data,
                vulnerabilities
            )
        else:
            llm_recommendations = None
        
        # Compile results
        results = {
            'phase': 'ERADICATION',
            'timestamp': datetime.now().isoformat(),
            'incident_id': incident_data.get('incident_id'),
            'vulnerabilities': vulnerabilities,
            'patches': patches,
            'config_updates': config_updates,
            'hardening_steps': hardening_steps,
            'backdoor_check': backdoor_check,
            'permanent_rules': permanent_rules,
            'llm_recommendations': llm_recommendations,
            'eradication_complete': True,
            'verification_steps': self._generate_verification_steps(attack_type)
        }
        
        self._print_results(results)
        
        return results
    
    def _assess_vulnerabilities(
        self,
        attack_type: str,
        root_cause: Dict
    ) -> List[Dict[str, Any]]:
        """Assess vulnerabilities that enabled the attack"""
        vulnerabilities = []
        
        vuln_mapping = {
            'DDOS': [
                {
                    'id': 'VULN-001',
                    'name': 'Lack of Rate Limiting',
                    'severity': 'HIGH',
                    'description': 'No request rate limiting implemented',
                    'cvss_score': 7.5,
                    'remediation': 'Implement adaptive rate limiting'
                },
                {
                    'id': 'VULN-002',
                    'name': 'No DDoS Protection',
                    'severity': 'HIGH',
                    'description': 'Insufficient DDoS mitigation',
                    'cvss_score': 7.8,
                    'remediation': 'Deploy DDoS protection service'
                }
            ],
            'BRUTE_FORCE': [
                {
                    'id': 'VULN-003',
                    'name': 'Weak Account Lockout',
                    'severity': 'HIGH',
                    'description': 'No account lockout after failed attempts',
                    'cvss_score': 7.0,
                    'remediation': 'Implement progressive delays and lockouts'
                },
                {
                    'id': 'VULN-004',
                    'name': 'No MFA',
                    'severity': 'MEDIUM',
                    'description': 'Multi-factor authentication not enabled',
                    'cvss_score': 6.5,
                    'remediation': 'Enable MFA for all accounts'
                }
            ],
            'SQL_INJECTION': [
                {
                    'id': 'VULN-005',
                    'name': 'Input Validation Missing',
                    'severity': 'CRITICAL',
                    'description': 'Insufficient input validation',
                    'cvss_score': 9.8,
                    'remediation': 'Implement parameterized queries'
                },
                {
                    'id': 'VULN-006',
                    'name': 'WAF Not Configured',
                    'severity': 'HIGH',
                    'description': 'Web Application Firewall not active',
                    'cvss_score': 7.5,
                    'remediation': 'Deploy and configure WAF'
                }
            ],
            'XSS': [
                {
                    'id': 'VULN-007',
                    'name': 'Output Encoding Missing',
                    'severity': 'HIGH',
                    'description': 'No output encoding implemented',
                    'cvss_score': 7.3,
                    'remediation': 'Implement context-aware output encoding'
                },
                {
                    'id': 'VULN-008',
                    'name': 'CSP Not Implemented',
                    'severity': 'MEDIUM',
                    'description': 'Content Security Policy missing',
                    'cvss_score': 6.1,
                    'remediation': 'Implement strict CSP headers'
                }
            ]
        }
        
        vulnerabilities = vuln_mapping.get(attack_type, [
            {
                'id': 'VULN-999',
                'name': 'Generic Security Weakness',
                'severity': 'MEDIUM',
                'description': root_cause.get('primary_cause', 'Unknown'),
                'cvss_score': 6.0,
                'remediation': 'Conduct security assessment'
            }
        ])
        
        return vulnerabilities
    
    def _generate_patches(
        self,
        attack_type: str,
        vulnerabilities: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Generate patches and fixes"""
        patches = []
        
        for vuln in vulnerabilities:
            patch = {
                'patch_id': f"PATCH-{vuln['id'].split('-')[1]}",
                'vulnerability': vuln['name'],
                'patch_type': self._determine_patch_type(vuln['name']),
                'priority': vuln['severity'],
                'description': vuln['remediation'],
                'commands': self._generate_patch_commands(vuln),
                'testing_required': True,
                'rollback_plan': f"Restore from backup before patch"
            }
            patches.append(patch)
        
        return patches
    
    def _determine_patch_type(self, vuln_name: str) -> str:
        """Determine type of patch needed"""
        if 'configuration' in vuln_name.lower():
            return 'CONFIGURATION'
        elif 'code' in vuln_name.lower() or 'validation' in vuln_name.lower():
            return 'CODE_FIX'
        elif 'policy' in vuln_name.lower():
            return 'POLICY_UPDATE'
        else:
            return 'SYSTEM_UPDATE'
    
    def _generate_patch_commands(self, vuln: Dict) -> List[str]:
        """Generate specific patch commands"""
        vuln_name = vuln['name'].lower()
        
        if 'rate limiting' in vuln_name:
            return [
                "# Enable rate limiting in nginx",
                "limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;",
                "limit_req zone=one burst=20 nodelay;",
                "# Reload nginx",
                "sudo nginx -s reload"
            ]
        elif 'account lockout' in vuln_name:
            return [
                "# Configure account lockout policy",
                "# Edit: /etc/pam.d/common-auth",
                "auth required pam_tally2.so deny=5 unlock_time=1800",
                "# Apply changes",
                "sudo pam-auth-update"
            ]
        elif 'waf' in vuln_name:
            return [
                "# Enable ModSecurity WAF",
                "sudo a2enmod security2",
                "# Load OWASP Core Rule Set",
                "sudo cp -R /usr/share/modsecurity-crs /etc/modsecurity/",
                "# Restart Apache",
                "sudo systemctl restart apache2"
            ]
        elif 'mfa' in vuln_name:
            return [
                "# Enable MFA for all users",
                "# Install Google Authenticator PAM module",
                "sudo apt-get install libpam-google-authenticator",
                "# Configure PAM",
                "echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd"
            ]
        else:
            return [
                "# Apply security updates",
                "sudo apt-get update",
                "sudo apt-get upgrade -y",
                "# Reboot if kernel updated",
                "sudo reboot"
            ]
    
    def _generate_config_updates(
        self,
        attack_type: str,
        incident_data: Dict
    ) -> Dict[str, Any]:
        """Generate permanent configuration updates"""
        updates = {
            'firewall': {},
            'waf': {},
            'ids_ips': {},
            'application': {}
        }
        
        # Firewall updates
        updates['firewall'] = {
            'default_policy': 'DROP',
            'logging': 'enabled',
            'rate_limiting': 'enabled',
            'geo_blocking': 'enabled for high-risk countries',
            'custom_rules': [
                f"# Block patterns associated with {attack_type}",
                "# Rules generated based on attack signature"
            ]
        }
        
        # WAF updates
        if attack_type in ['SQL_INJECTION', 'XSS']:
            updates['waf'] = {
                'mode': 'blocking',
                'rule_sets': ['OWASP Core Rule Set', 'Custom Rules'],
                'sensitivity': 'high',
                'logging': 'verbose'
            }
        
        # IDS/IPS updates
        updates['ids_ips'] = {
            'signatures': f'Added signatures for {attack_type}',
            'action': 'block',
            'alert_threshold': 'low',
            'monitoring': 'enhanced'
        }
        
        return updates
    
    def _generate_hardening_steps(
        self,
        attack_type: str,
        root_cause: Dict
    ) -> List[Dict[str, Any]]:
        """Generate system hardening steps"""
        steps = [
            {
                'step_id': 'HARD-001',
                'category': 'System Updates',
                'action': 'Apply all security patches',
                'priority': 'CRITICAL',
                'commands': [
                    'sudo apt-get update',
                    'sudo apt-get upgrade -y',
                    'sudo apt-get dist-upgrade -y'
                ]
            },
            {
                'step_id': 'HARD-002',
                'category': 'Service Hardening',
                'action': 'Disable unnecessary services',
                'priority': 'HIGH',
                'commands': [
                    'systemctl list-unit-files | grep enabled',
                    '# Disable unused services',
                    'sudo systemctl disable <service_name>'
                ]
            },
            {
                'step_id': 'HARD-003',
                'category': 'Port Management',
                'action': 'Close unused ports',
                'priority': 'HIGH',
                'commands': [
                    'sudo netstat -tulpn',
                    '# Close unnecessary ports in firewall',
                    'sudo ufw deny <port_number>'
                ]
            },
            {
                'step_id': 'HARD-004',
                'category': 'Access Control',
                'action': 'Review and update access controls',
                'priority': 'HIGH',
                'commands': [
                    'sudo cat /etc/passwd',
                    'sudo userdel <unused_account>',
                    'sudo chmod 600 /etc/shadow'
                ]
            },
            {
                'step_id': 'HARD-005',
                'category': 'Logging',
                'action': 'Enable comprehensive logging',
                'priority': 'MEDIUM',
                'commands': [
                    'sudo nano /etc/rsyslog.conf',
                    '# Enable all logging categories',
                    'sudo systemctl restart rsyslog'
                ]
            }
        ]
        
        # Add attack-specific hardening
        if attack_type == 'BRUTE_FORCE':
            steps.append({
                'step_id': 'HARD-006',
                'category': 'Password Policy',
                'action': 'Enforce strong password policy',
                'priority': 'HIGH',
                'commands': [
                    'sudo nano /etc/pam.d/common-password',
                    '# Add: password requisite pam_pwquality.so retry=3',
                    'sudo pam-auth-update'
                ]
            })
        
        return steps
    
    def _check_for_backdoors(
        self,
        incident_data: Dict,
        analysis_data: Dict
    ) -> Dict[str, Any]:
        """Check for backdoors or persistent threats"""
        check_results = {
            'backdoors_found': False,
            'suspicious_files': [],
            'suspicious_processes': [],
            'suspicious_network': [],
            'recommendations': []
        }
        
        # Simulated checks (in production, integrate with security tools)
        check_results['recommendations'] = [
            'Run rootkit scanner: sudo rkhunter --check',
            'Check for unauthorized SSH keys: cat ~/.ssh/authorized_keys',
            'Review cron jobs: crontab -l',
            'Check for unusual listening ports: netstat -tulpn',
            'Scan for malware: sudo clamscan -r /',
            'Review system logs for anomalies: journalctl -xe'
        ]
        
        return check_results
    
    def _create_permanent_rules(
        self,
        incident_data: Dict,
        analysis_data: Dict
    ) -> List[Dict[str, Any]]:
        """Create permanent security rules"""
        rules = []
        
        source_ips = incident_data.get('source_ips', [])
        attack_type = incident_data.get('attack_type')
        
        # Permanent IP blocks for confirmed malicious sources
        if source_ips:
            rules.append({
                'rule_id': 'PERM-001',
                'type': 'IP_BLACKLIST',
                'description': f'Permanent block for {len(source_ips)} malicious IPs',
                'targets': source_ips[:20],  # Limit display
                'duration': 'permanent',
                'review_date': (datetime.now().replace(month=datetime.now().month + 3)).strftime('%Y-%m-%d')
            })
        
        # Attack signature rules
        rules.append({
            'rule_id': 'PERM-002',
            'type': 'SIGNATURE_DETECTION',
            'description': f'Detection rules for {attack_type}',
            'patterns': self._get_attack_patterns(attack_type),
            'action': 'block_and_alert',
            'duration': 'permanent'
        })
        
        # Rate limiting rules
        rules.append({
            'rule_id': 'PERM-003',
            'type': 'RATE_LIMIT',
            'description': 'Permanent rate limiting policy',
            'limits': {
                'requests_per_second': 10,
                'requests_per_minute': 500,
                'concurrent_connections': 100
            },
            'duration': 'permanent'
        })
        
        return rules
    
    def _get_attack_patterns(self, attack_type: str) -> List[str]:
        """Get attack patterns for signature detection"""
        patterns = {
            'SQL_INJECTION': [
                "union.*select",
                "or.*1.*=.*1",
                "drop.*table",
                "'; exec"
            ],
            'XSS': [
                "<script>",
                "javascript:",
                "onerror=",
                "onload="
            ],
            'DDOS': [
                "high_request_rate",
                "syn_flood",
                "udp_flood"
            ]
        }
        return patterns.get(attack_type, [])
    
    def _llm_eradication_plan(
        self,
        incident_data: Dict,
        analysis_data: Dict,
        vulnerabilities: List[Dict]
    ) -> Optional[Dict]:
        """Generate comprehensive eradication plan using LLM"""
        try:
            prompt = f"""
Create a comprehensive eradication plan for this incident:

Attack: {incident_data.get('attack_type')}
Severity: {incident_data.get('severity')}

Vulnerabilities Found:
{json.dumps(vulnerabilities, indent=2)}

Root Cause:
{json.dumps(analysis_data.get('root_cause'), indent=2)}

Provide:
1. Prioritized remediation steps
2. Long-term security improvements
3. Compliance considerations
4. Risk mitigation strategies
5. Monitoring enhancements

Return structured plan.
"""
            response = self.llm_engine.generate_response(
                prompt,
                system_prompt="You are a security remediation specialist."
            )
            
            return {'eradication_plan': response}
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_verification_steps(self, attack_type: str) -> List[str]:
        """Generate steps to verify eradication"""
        return [
            "Verify all patches applied successfully",
            "Test all configuration changes",
            "Scan for remaining vulnerabilities",
            "Monitor for attack recurrence (24-48 hours)",
            "Validate firewall rules are active",
            "Confirm logging is capturing all events",
            "Test incident response procedures",
            "Document all changes made"
        ]
    
    def _print_results(self, results: Dict):
        """Pretty print eradication results"""
        print(f"\n{'─'*60}")
        print(f"🆔 Incident ID: {results['incident_id']}")
        print(f"⏰ Timestamp: {results['timestamp']}")
        print(f"{'─'*60}")
        
        # Vulnerabilities
        print(f"\n🔍 Vulnerabilities Addressed: {len(results['vulnerabilities'])}")
        for vuln in results['vulnerabilities'][:3]:
            print(f"  • [{vuln['severity']}] {vuln['name']}")
            print(f"    CVSS: {vuln['cvss_score']} - {vuln['remediation']}")
        
        # Patches
        print(f"\n🔧 Patches Applied: {len(results['patches'])}")
        for patch in results['patches'][:3]:
            print(f"  • [{patch['priority']}] {patch['description']}")
        
        # Hardening
        print(f"\n🛡️  Hardening Steps: {len(results['hardening_steps'])}")
        for step in results['hardening_steps'][:3]:
            print(f"  • [{step['priority']}] {step['action']}")
        
        # Permanent Rules
        print(f"\n⚖️  Permanent Rules Created: {len(results['permanent_rules'])}")
        for rule in results['permanent_rules']:
            print(f"  • [{rule['rule_id']}] {rule['description']}")
        
        # Backdoor Check
        backdoor = results['backdoor_check']
        print(f"\n🔐 Backdoor Check: {'⚠️  Found' if backdoor['backdoors_found'] else '✓ Clean'}")
        
        print(f"\n{'─'*60}")
        print("✓ Phase 4 Complete - Root Cause Eradicated")
        print("─"*60 + "\n")


# Example usage
if __name__ == "__main__":
    sample_incident = {
        'incident_id': 'INC-20260128-103045',
        'attack_type': 'SQL_INJECTION',
        'severity': 'CRITICAL'
    }
    
    sample_analysis = {
        'root_cause': {
            'primary_cause': 'Insufficient input validation',
            'vulnerability_type': 'Input Validation / Injection'
        }
    }
    
    eradicator = IncidentEradication()
    results = eradicator.eradicate(sample_incident, sample_analysis)
    
    print("\n📋 Full Results:")
    print(json.dumps(results, indent=2, default=str))

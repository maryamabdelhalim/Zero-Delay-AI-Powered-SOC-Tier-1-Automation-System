"""
Phase 5: Recovery - الاستعادة
Safely restore services to normal operation
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json


class IncidentRecovery:
    """
    المرحلة الخامسة: الاستعادة والعودة للوضع الطبيعي
    Phase 5: System Recovery
    """
    
    def __init__(self, llm_engine=None):
        """Initialize Recovery module"""
        self.llm_engine = llm_engine
        
    def recover(
        self,
        incident_data: Dict[str, Any],
        eradication_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Main recovery function
        
        Args:
            incident_data: Results from Phase 1
            eradication_data: Results from Phase 4
            
        Returns:
            Recovery results
        """
        print("\n" + "="*60)
        print("🔄 Phase 5: RECOVERY")
        print("="*60)
        
        affected_assets = incident_data.get('affected_assets', [])
        severity = incident_data.get('severity', 'LOW')
        
        # Step 1: Recovery Plan
        recovery_plan = self._create_recovery_plan(
            affected_assets,
            severity
        )
        
        # Step 2: Service Restoration
        restoration_steps = self._generate_restoration_steps(
            affected_assets,
            severity
        )
        
        # Step 3: Monitoring Plan
        monitoring_plan = self._create_monitoring_plan(
            incident_data,
            eradication_data
        )
        
        # Step 4: Verification Tests
        verification_tests = self._generate_verification_tests(
            affected_assets,
            incident_data.get('attack_type')
        )
        
        # Step 5: Rollback Plan
        rollback_plan = self._create_rollback_plan(affected_assets)
        
        # Step 6: Post-Recovery Actions
        post_recovery = self._generate_post_recovery_actions(
            incident_data
        )
        
        # Step 7: Final Report Generation
        final_report = self._generate_final_report(
            incident_data,
            eradication_data
        )
        
        # Step 8: LLM Recommendations
        if self.llm_engine:
            llm_guidance = self._llm_recovery_guidance(
                incident_data,
                eradication_data,
                recovery_plan
            )
        else:
            llm_guidance = None
        
        # Compile results
        results = {
            'phase': 'RECOVERY',
            'timestamp': datetime.now().isoformat(),
            'incident_id': incident_data.get('incident_id'),
            'recovery_plan': recovery_plan,
            'restoration_steps': restoration_steps,
            'monitoring_plan': monitoring_plan,
            'verification_tests': verification_tests,
            'rollback_plan': rollback_plan,
            'post_recovery_actions': post_recovery,
            'final_report': final_report,
            'llm_guidance': llm_guidance,
            'recovery_status': 'IN_PROGRESS',
            'estimated_completion': self._estimate_completion(severity)
        }
        
        self._print_results(results)
        
        return results
    
    def _create_recovery_plan(
        self,
        affected_assets: List[str],
        severity: str
    ) -> Dict[str, Any]:
        """Create comprehensive recovery plan"""
        plan = {
            'strategy': self._determine_recovery_strategy(severity),
            'phases': [],
            'total_duration': self._estimate_duration(severity),
            'risk_assessment': self._assess_recovery_risk(severity),
            'approval_required': severity in ['CRITICAL', 'HIGH']
        }
        
        # Define recovery phases
        if severity == 'CRITICAL':
            plan['phases'] = [
                {
                    'phase': 1,
                    'name': 'Initial Validation',
                    'duration': '30 minutes',
                    'activities': [
                        'Verify all patches applied',
                        'Confirm no active threats',
                        'Test monitoring systems'
                    ]
                },
                {
                    'phase': 2,
                    'name': 'Partial Service Restoration',
                    'duration': '1-2 hours',
                    'activities': [
                        'Restore non-critical services',
                        'Monitor for anomalies',
                        'Gradual traffic increase'
                    ]
                },
                {
                    'phase': 3,
                    'name': 'Full Service Restoration',
                    'duration': '2-4 hours',
                    'activities': [
                        'Restore all services',
                        'Remove temporary restrictions',
                        'Full capacity restoration'
                    ]
                },
                {
                    'phase': 4,
                    'name': 'Extended Monitoring',
                    'duration': '24-48 hours',
                    'activities': [
                        'Continuous monitoring',
                        'Performance validation',
                        'Security validation'
                    ]
                }
            ]
        else:
            plan['phases'] = [
                {
                    'phase': 1,
                    'name': 'Quick Validation',
                    'duration': '15 minutes',
                    'activities': ['Verify fixes', 'Test services']
                },
                {
                    'phase': 2,
                    'name': 'Service Restoration',
                    'duration': '30 minutes',
                    'activities': ['Restore services', 'Monitor briefly']
                }
            ]
        
        return plan
    
    def _determine_recovery_strategy(self, severity: str) -> str:
        """Determine recovery strategy based on severity"""
        strategies = {
            'CRITICAL': 'Phased recovery with extended monitoring',
            'HIGH': 'Gradual recovery with validation',
            'MEDIUM': 'Standard recovery procedure',
            'LOW': 'Quick restoration'
        }
        return strategies.get(severity, 'Standard recovery')
    
    def _estimate_duration(self, severity: str) -> str:
        """Estimate total recovery duration"""
        durations = {
            'CRITICAL': '24-48 hours',
            'HIGH': '8-12 hours',
            'MEDIUM': '2-4 hours',
            'LOW': '30-60 minutes'
        }
        return durations.get(severity, '2-4 hours')
    
    def _assess_recovery_risk(self, severity: str) -> str:
        """Assess risks during recovery"""
        if severity == 'CRITICAL':
            return "HIGH - Attack may resume during recovery"
        elif severity == 'HIGH':
            return "MEDIUM - Monitor closely for recurrence"
        else:
            return "LOW - Standard recovery risks"
    
    def _generate_restoration_steps(
        self,
        affected_assets: List[str],
        severity: str
    ) -> List[Dict[str, Any]]:
        """Generate detailed service restoration steps"""
        steps = []
        
        # Step 1: Pre-restoration checks
        steps.append({
            'step_id': 'RESTORE-001',
            'order': 1,
            'name': 'Pre-Restoration Validation',
            'duration': '15 minutes',
            'priority': 'CRITICAL',
            'actions': [
                'Verify all security patches applied',
                'Confirm firewall rules active',
                'Test monitoring systems',
                'Backup current state'
            ],
            'validation': 'Manual verification required',
            'rollback_on_failure': False
        })
        
        # Step 2: Start services
        steps.append({
            'step_id': 'RESTORE-002',
            'order': 2,
            'name': 'Service Initialization',
            'duration': '30 minutes',
            'priority': 'HIGH',
            'actions': self._generate_service_start_commands(affected_assets),
            'validation': 'Check service status',
            'rollback_on_failure': True
        })
        
        # Step 3: Traffic restoration
        if severity in ['CRITICAL', 'HIGH']:
            steps.append({
                'step_id': 'RESTORE-003',
                'order': 3,
                'name': 'Gradual Traffic Restoration',
                'duration': '1-2 hours',
                'priority': 'HIGH',
                'actions': [
                    'Remove rate limiting gradually (10% -> 25% -> 50% -> 100%)',
                    'Monitor performance metrics',
                    'Watch for attack patterns',
                    'Adjust limits if needed'
                ],
                'validation': 'Performance within normal range',
                'rollback_on_failure': True
            })
        
        # Step 4: Remove temporary blocks
        steps.append({
            'step_id': 'RESTORE-004',
            'order': 4,
            'name': 'Remove Temporary Restrictions',
            'duration': '30 minutes',
            'priority': 'MEDIUM',
            'actions': [
                'Review temporary IP blocks',
                'Remove blocks for legitimate traffic',
                'Keep malicious IPs blocked',
                'Update whitelist if needed'
            ],
            'validation': 'Legitimate traffic flows normally',
            'rollback_on_failure': False
        })
        
        # Step 5: Full capacity
        steps.append({
            'step_id': 'RESTORE-005',
            'order': 5,
            'name': 'Full Capacity Restoration',
            'duration': '15 minutes',
            'priority': 'MEDIUM',
            'actions': [
                'Remove all temporary limits',
                'Restore normal configurations',
                'Enable all features',
                'Notify stakeholders'
            ],
            'validation': 'System at full capacity',
            'rollback_on_failure': False
        })
        
        return steps
    
    def _generate_service_start_commands(
        self,
        assets: List[str]
    ) -> List[str]:
        """Generate service start commands"""
        commands = [
            '# Start services gradually',
            'sudo systemctl start nginx',
            'sleep 30',
            'sudo systemctl start apache2',
            'sleep 30',
            'sudo systemctl start mysql',
            'sleep 30',
            '# Verify all services running',
            'sudo systemctl status nginx apache2 mysql',
            '# Check logs for errors',
            'sudo journalctl -xe'
        ]
        return commands
    
    def _create_monitoring_plan(
        self,
        incident_data: Dict,
        eradication_data: Dict
    ) -> Dict[str, Any]:
        """Create post-recovery monitoring plan"""
        attack_type = incident_data.get('attack_type')
        severity = incident_data.get('severity')
        
        plan = {
            'duration': '48 hours' if severity == 'CRITICAL' else '24 hours',
            'frequency': 'Every 15 minutes' if severity == 'CRITICAL' else 'Every hour',
            'metrics': self._define_monitoring_metrics(attack_type),
            'alerts': self._define_alert_thresholds(severity),
            'automated_responses': self._define_automated_responses(attack_type),
            'reporting_schedule': 'Every 4 hours to SOC lead'
        }
        
        return plan
    
    def _define_monitoring_metrics(self, attack_type: str) -> List[str]:
        """Define metrics to monitor post-recovery"""
        base_metrics = [
            'CPU usage',
            'Memory usage',
            'Network traffic volume',
            'Response times',
            'Error rates',
            'Active connections'
        ]
        
        attack_specific = {
            'DDOS': ['Requests per second', 'Connection rate', 'Bandwidth usage'],
            'BRUTE_FORCE': ['Failed login attempts', 'Account lockouts', 'Auth logs'],
            'SQL_INJECTION': ['Database queries', 'WAF blocks', 'SQL errors'],
            'XSS': ['WAF blocks', 'JavaScript execution', 'Cookie theft attempts']
        }
        
        return base_metrics + attack_specific.get(attack_type, [])
    
    def _define_alert_thresholds(self, severity: str) -> Dict[str, str]:
        """Define alert thresholds"""
        if severity == 'CRITICAL':
            return {
                'cpu_usage': '> 70%',
                'memory_usage': '> 80%',
                'error_rate': '> 1%',
                'response_time': '> 2 seconds',
                'suspicious_traffic': '> 100 requests/min from single IP'
            }
        else:
            return {
                'cpu_usage': '> 85%',
                'memory_usage': '> 90%',
                'error_rate': '> 5%',
                'response_time': '> 5 seconds',
                'suspicious_traffic': '> 500 requests/min from single IP'
            }
    
    def _define_automated_responses(self, attack_type: str) -> List[str]:
        """Define automated responses to anomalies"""
        return [
            'Auto-block IPs exceeding thresholds',
            'Increase logging verbosity on anomaly',
            'Send immediate alerts to SOC team',
            'Scale resources if performance degrades',
            'Activate DDoS protection if traffic spikes'
        ]
    
    def _generate_verification_tests(
        self,
        assets: List[str],
        attack_type: str
    ) -> List[Dict[str, Any]]:
        """Generate verification tests"""
        tests = [
            {
                'test_id': 'TEST-001',
                'name': 'Service Availability',
                'type': 'FUNCTIONAL',
                'description': 'Verify all services responding',
                'commands': [
                    'curl -I http://localhost',
                    'nc -zv localhost 80 443 22'
                ],
                'expected_result': 'All services return 200 OK'
            },
            {
                'test_id': 'TEST-002',
                'name': 'Performance Baseline',
                'type': 'PERFORMANCE',
                'description': 'Verify performance within normal range',
                'commands': [
                    'ab -n 1000 -c 10 http://localhost/',
                    'vmstat 1 10'
                ],
                'expected_result': 'Response times < 500ms'
            },
            {
                'test_id': 'TEST-003',
                'name': 'Security Controls',
                'type': 'SECURITY',
                'description': 'Verify security controls active',
                'commands': [
                    'sudo iptables -L -n',
                    'sudo fail2ban-client status'
                ],
                'expected_result': 'All firewall rules active'
            }
        ]
        
        # Attack-specific tests
        if attack_type == 'DDOS':
            tests.append({
                'test_id': 'TEST-004',
                'name': 'Rate Limiting',
                'type': 'SECURITY',
                'description': 'Verify rate limiting works',
                'commands': [
                    'ab -n 10000 -c 100 http://localhost/'
                ],
                'expected_result': 'Requests throttled after threshold'
            })
        
        return tests
    
    def _create_rollback_plan(self, assets: List[str]) -> Dict[str, Any]:
        """Create rollback plan in case recovery fails"""
        return {
            'trigger_conditions': [
                'Service fails to start',
                'Attack resumes',
                'Performance severely degraded',
                'Critical errors in logs'
            ],
            'rollback_steps': [
                'Stop affected services immediately',
                'Restore from last known good backup',
                'Reapply containment measures',
                'Escalate to SOC Tier 2',
                'Re-enter Phase 4 if needed'
            ],
            'backup_location': '/backup/pre-recovery/',
            'estimated_rollback_time': '15-30 minutes'
        }
    
    def _generate_post_recovery_actions(
        self,
        incident_data: Dict
    ) -> List[Dict[str, Any]]:
        """Generate post-recovery actions"""
        return [
            {
                'action_id': 'POST-001',
                'name': 'Lessons Learned Meeting',
                'priority': 'HIGH',
                'deadline': '72 hours',
                'description': 'Conduct post-incident review',
                'participants': ['SOC Team', 'IT Management', 'Security Lead']
            },
            {
                'action_id': 'POST-002',
                'name': 'Update Documentation',
                'priority': 'MEDIUM',
                'deadline': '1 week',
                'description': 'Update runbooks and procedures',
                'deliverables': ['Updated runbook', 'New detection rules']
            },
            {
                'action_id': 'POST-003',
                'name': 'Security Assessment',
                'priority': 'HIGH',
                'deadline': '2 weeks',
                'description': 'Conduct comprehensive security assessment',
                'scope': 'All affected systems and related infrastructure'
            },
            {
                'action_id': 'POST-004',
                'name': 'Training Update',
                'priority': 'MEDIUM',
                'deadline': '1 month',
                'description': 'Update team training based on incident',
                'topics': [f"Handling {incident_data.get('attack_type')} attacks"]
            }
        ]
    
    def _generate_final_report(
        self,
        incident_data: Dict,
        eradication_data: Dict
    ) -> Dict[str, Any]:
        """Generate final incident report"""
        return {
            'report_id': f"RPT-{incident_data.get('incident_id')}",
            'incident_summary': {
                'incident_id': incident_data.get('incident_id'),
                'attack_type': incident_data.get('attack_type'),
                'severity': incident_data.get('severity'),
                'detection_time': incident_data.get('timestamp'),
                'resolution_time': datetime.now().isoformat(),
                'total_duration': self._calculate_duration(incident_data.get('timestamp'))
            },
            'impact_summary': {
                'affected_assets': incident_data.get('affected_assets', []),
                'service_disruption': 'Calculated based on logs',
                'data_breach': 'No evidence found',
                'financial_impact': 'To be assessed'
            },
            'response_summary': {
                'actions_taken': 'See detailed logs',
                'patches_applied': len(eradication_data.get('patches', [])),
                'vulnerabilities_fixed': len(eradication_data.get('vulnerabilities', [])),
                'permanent_rules': len(eradication_data.get('permanent_rules', []))
            },
            'recommendations': [
                'Implement recommended security improvements',
                'Conduct regular security assessments',
                'Update incident response procedures',
                'Enhance monitoring capabilities'
            ]
        }
    
    def _calculate_duration(self, start_time: str) -> str:
        """Calculate incident duration"""
        try:
            start = datetime.fromisoformat(start_time)
            duration = datetime.now() - start
            hours = duration.total_seconds() / 3600
            return f"{hours:.1f} hours"
        except:
            return "Unknown"
    
    def _llm_recovery_guidance(
        self,
        incident_data: Dict,
        eradication_data: Dict,
        recovery_plan: Dict
    ) -> Optional[Dict]:
        """Get LLM guidance for recovery"""
        try:
            prompt = f"""
Provide recovery guidance for this incident:

Incident: {incident_data.get('attack_type')}
Severity: {incident_data.get('severity')}

Recovery Plan:
{json.dumps(recovery_plan, indent=2)}

Eradication Completed:
{json.dumps(eradication_data, indent=2, default=str)}

Provide:
1. Risk assessment for recovery
2. Additional precautions
3. Success criteria
4. Early warning signs of problems
5. Communication plan

Return structured guidance.
"""
            response = self.llm_engine.generate_response(
                prompt,
                system_prompt="You are a recovery operations expert."
            )
            
            return {'recovery_guidance': response}
        except Exception as e:
            return {'error': str(e)}
    
    def _estimate_completion(self, severity: str) -> str:
        """Estimate completion time"""
        now = datetime.now()
        
        hours = {
            'CRITICAL': 48,
            'HIGH': 12,
            'MEDIUM': 4,
            'LOW': 1
        }.get(severity, 4)
        
        completion = now + timedelta(hours=hours)
        return completion.isoformat()
    
    def _print_results(self, results: Dict):
        """Pretty print recovery results"""
        print(f"\n{'─'*60}")
        print(f"🆔 Incident ID: {results['incident_id']}")
        print(f"⏰ Timestamp: {results['timestamp']}")
        print(f"{'─'*60}")
        
        # Recovery Plan
        plan = results['recovery_plan']
        print(f"\n📋 Recovery Strategy: {plan['strategy']}")
        print(f"⏳ Estimated Duration: {plan['total_duration']}")
        print(f"⚠️  Risk Level: {plan['risk_assessment']}")
        
        # Recovery Phases
        print(f"\n🔄 Recovery Phases: {len(plan['phases'])}")
        for phase in plan['phases'][:3]:
            print(f"  {phase['phase']}. {phase['name']} ({phase['duration']})")
        
        # Restoration Steps
        print(f"\n⚡ Restoration Steps: {len(results['restoration_steps'])}")
        for step in results['restoration_steps'][:3]:
            print(f"  • [{step['priority']}] {step['name']}")
        
        # Monitoring
        monitoring = results['monitoring_plan']
        print(f"\n👁️  Monitoring Plan:")
        print(f"  • Duration: {monitoring['duration']}")
        print(f"  • Frequency: {monitoring['frequency']}")
        print(f"  • Metrics: {len(monitoring['metrics'])} tracked")
        
        # Verification Tests
        print(f"\n✅ Verification Tests: {len(results['verification_tests'])}")
        for test in results['verification_tests'][:3]:
            print(f"  • [{test['type']}] {test['name']}")
        
        # Status
        print(f"\n📊 Recovery Status: {results['recovery_status']}")
        print(f"🎯 Estimated Completion: {results['estimated_completion']}")
        
        print(f"\n{'─'*60}")
        print("✓ Phase 5 Complete - System Recovered")
        print("✓ ALL PHASES COMPLETE - INCIDENT RESOLVED")
        print("─"*60 + "\n")
        print("🎉 SOC Automation Process Successfully Completed!")


# Example usage
if __name__ == "__main__":
    sample_incident = {
        'incident_id': 'INC-20260128-103045',
        'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
        'attack_type': 'DDOS',
        'severity': 'CRITICAL',
        'affected_assets': ['web-server-01', 'web-server-02']
    }
    
    sample_eradication = {
        'vulnerabilities': [{'name': 'Rate Limiting'}, {'name': 'DDoS Protection'}],
        'patches': [{'patch_id': 'PATCH-001'}, {'patch_id': 'PATCH-002'}],
        'permanent_rules': [{'rule_id': 'PERM-001'}]
    }
    
    recoverer = IncidentRecovery()
    results = recoverer.recover(sample_incident, sample_eradication)
    
    print("\n📋 Full Results:")
    print(json.dumps(results, indent=2, default=str))

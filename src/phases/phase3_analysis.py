"""
Phase 3: Analysis - التحليل العميق
Deep analysis of attack methodology and impact
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import re


class IncidentAnalysis:
    """
    المرحلة الثالثة: التحليل العميق
    Phase 3: Deep Incident Analysis
    """
    
    def __init__(self, llm_engine=None):
        """Initialize Analysis module"""
        self.llm_engine = llm_engine
        
    def analyze(
        self,
        incident_data: Dict[str, Any],
        containment_data: Dict[str, Any],
        log_data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main analysis function
        
        Args:
            incident_data: Results from Phase 1
            containment_data: Results from Phase 2
            log_data: Raw log data for deep analysis
            
        Returns:
            Analysis results
        """
        print("\n" + "="*60)
        print("🔬 Phase 3: ANALYSIS")
        print("="*60)
        
        # Step 1: Attack Vector Analysis
        attack_vector = self._analyze_attack_vector(
            incident_data,
            log_data
        )
        
        # Step 2: Timeline Construction
        timeline = self._construct_timeline(
            incident_data,
            containment_data
        )
        
        # Step 3: Source Analysis
        source_analysis = self._analyze_sources(
            incident_data.get('source_ips', []),
            incident_data.get('attack_type')
        )
        
        # Step 4: Impact Assessment
        impact = self._assess_impact(
            incident_data,
            containment_data
        )
        
        # Step 5: Pattern Analysis
        patterns = self._analyze_patterns(log_data) if log_data else {}
        
        # Step 6: Root Cause Analysis
        root_cause = self._identify_root_cause(
            incident_data,
            patterns,
            attack_vector
        )
        
        # Step 7: LLM Deep Analysis
        if self.llm_engine:
            llm_analysis = self._llm_deep_analysis(
                incident_data,
                containment_data,
                attack_vector,
                log_data
            )
        else:
            llm_analysis = None
        
        # Compile results
        results = {
            'phase': 'ANALYSIS',
            'timestamp': datetime.now().isoformat(),
            'incident_id': incident_data.get('incident_id'),
            'attack_vector': attack_vector,
            'timeline': timeline,
            'source_analysis': source_analysis,
            'impact_assessment': impact,
            'patterns': patterns,
            'root_cause': root_cause,
            'llm_insights': llm_analysis,
            'next_steps': self._generate_next_steps(root_cause, impact)
        }
        
        self._print_results(results)
        
        return results
    
    def _analyze_attack_vector(
        self,
        incident_data: Dict,
        log_data: Optional[str]
    ) -> Dict[str, Any]:
        """Analyze how the attack was executed"""
        attack_type = incident_data.get('attack_type', 'UNKNOWN')
        
        vector = {
            'attack_type': attack_type,
            'methodology': self._determine_methodology(attack_type),
            'entry_points': [],
            'techniques': [],
            'sophistication': 'MEDIUM'
        }
        
        # Determine entry points
        if log_data:
            if 'port 80' in log_data.lower() or 'http' in log_data.lower():
                vector['entry_points'].append('HTTP/80')
            if 'port 443' in log_data.lower() or 'https' in log_data.lower():
                vector['entry_points'].append('HTTPS/443')
            if 'ssh' in log_data.lower() or 'port 22' in log_data.lower():
                vector['entry_points'].append('SSH/22')
        
        # Determine techniques based on attack type
        techniques_map = {
            'DDOS': ['SYN Flood', 'UDP Flood', 'HTTP Flood'],
            'BRUTE_FORCE': ['Dictionary Attack', 'Credential Stuffing'],
            'SQL_INJECTION': ['Union-based SQLi', 'Blind SQLi'],
            'XSS': ['Reflected XSS', 'Stored XSS'],
            'PORT_SCAN': ['TCP SYN Scan', 'Service Enumeration']
        }
        
        vector['techniques'] = techniques_map.get(attack_type, ['Unknown'])
        
        # Assess sophistication
        if len(incident_data.get('source_ips', [])) > 50:
            vector['sophistication'] = 'HIGH'
        elif len(incident_data.get('source_ips', [])) > 10:
            vector['sophistication'] = 'MEDIUM'
        else:
            vector['sophistication'] = 'LOW'
        
        return vector
    
    def _determine_methodology(self, attack_type: str) -> str:
        """Determine attack methodology"""
        methodologies = {
            'DDOS': 'Distributed volumetric attack using multiple source IPs to overwhelm target resources',
            'DOS': 'Single-source attack aimed at exhausting target resources',
            'BRUTE_FORCE': 'Systematic credential guessing using automated tools',
            'SQL_INJECTION': 'Injection of malicious SQL queries to manipulate database',
            'XSS': 'Injection of malicious scripts into web pages',
            'PORT_SCAN': 'Network reconnaissance to identify open ports and services',
            'MALWARE': 'Deployment of malicious software to compromise systems'
        }
        
        return methodologies.get(attack_type, 'Unknown attack methodology')
    
    def _construct_timeline(
        self,
        incident_data: Dict,
        containment_data: Dict
    ) -> List[Dict[str, str]]:
        """Construct incident timeline"""
        timeline = []
        
        # Parse timestamps
        incident_time = datetime.fromisoformat(
            incident_data.get('timestamp', datetime.now().isoformat())
        )
        containment_time = datetime.fromisoformat(
            containment_data.get('timestamp', datetime.now().isoformat())
        )
        
        # Initial detection
        timeline.append({
            'timestamp': incident_time.isoformat(),
            'event': 'Initial Detection',
            'description': f"{incident_data.get('attack_type')} attack detected",
            'phase': 'IDENTIFICATION'
        })
        
        # Estimate attack start (30 mins before detection)
        attack_start = incident_time - timedelta(minutes=30)
        timeline.append({
            'timestamp': attack_start.isoformat(),
            'event': 'Attack Initiation (estimated)',
            'description': 'Attack traffic began',
            'phase': 'PRE-DETECTION'
        })
        
        # Containment
        timeline.append({
            'timestamp': containment_time.isoformat(),
            'event': 'Containment Actions',
            'description': f"Blocked {containment_data.get('blocked_count', 0)} IPs",
            'phase': 'CONTAINMENT'
        })
        
        # Analysis
        timeline.append({
            'timestamp': datetime.now().isoformat(),
            'event': 'Deep Analysis',
            'description': 'Analyzing attack vector and impact',
            'phase': 'ANALYSIS'
        })
        
        return sorted(timeline, key=lambda x: x['timestamp'])
    
    def _analyze_sources(
        self,
        source_ips: List[str],
        attack_type: str
    ) -> Dict[str, Any]:
        """Analyze attack sources"""
        analysis = {
            'total_ips': len(source_ips),
            'ip_distribution': {},
            'geographic_distribution': {},
            'threat_intelligence': []
        }
        
        # Analyze IP ranges
        ip_ranges = {}
        for ip in source_ips:
            # Get /24 network
            network = '.'.join(ip.split('.')[:3]) + '.0/24'
            ip_ranges[network] = ip_ranges.get(network, 0) + 1
        
        analysis['ip_distribution'] = ip_ranges
        
        # Simulate geographic analysis (in production, use GeoIP)
        analysis['geographic_distribution'] = {
            'Unknown': len(source_ips)
        }
        
        # Threat assessment
        if len(source_ips) > 100:
            analysis['threat_intelligence'].append(
                "Large-scale coordinated attack from botnet"
            )
        elif len(source_ips) > 10:
            analysis['threat_intelligence'].append(
                "Medium-scale attack, possibly compromised hosts"
            )
        else:
            analysis['threat_intelligence'].append(
                "Small-scale attack, single actor or small group"
            )
        
        return analysis
    
    def _assess_impact(
        self,
        incident_data: Dict,
        containment_data: Dict
    ) -> Dict[str, Any]:
        """Assess incident impact"""
        severity = incident_data.get('severity', 'LOW')
        affected_assets = incident_data.get('affected_assets', [])
        
        impact = {
            'severity': severity,
            'affected_systems': len(affected_assets),
            'service_disruption': self._estimate_disruption(severity),
            'data_breach_risk': self._assess_data_risk(incident_data),
            'financial_impact': self._estimate_financial_impact(severity, len(affected_assets)),
            'reputation_impact': self._assess_reputation_impact(severity)
        }
        
        return impact
    
    def _estimate_disruption(self, severity: str) -> str:
        """Estimate service disruption level"""
        disruption_map = {
            'CRITICAL': 'Complete service outage',
            'HIGH': 'Severe degradation',
            'MEDIUM': 'Moderate performance impact',
            'LOW': 'Minimal impact'
        }
        return disruption_map.get(severity, 'Unknown')
    
    def _assess_data_risk(self, incident_data: Dict) -> str:
        """Assess data breach risk"""
        attack_type = incident_data.get('attack_type')
        
        high_risk_attacks = ['SQL_INJECTION', 'MALWARE']
        medium_risk_attacks = ['XSS', 'BRUTE_FORCE']
        
        if attack_type in high_risk_attacks:
            return "HIGH - Potential data exfiltration"
        elif attack_type in medium_risk_attacks:
            return "MEDIUM - Credential compromise possible"
        else:
            return "LOW - Availability attack only"
    
    def _estimate_financial_impact(self, severity: str, num_assets: int) -> str:
        """Estimate financial impact"""
        base_impact = {
            'CRITICAL': 100000,
            'HIGH': 50000,
            'MEDIUM': 10000,
            'LOW': 1000
        }
        
        impact = base_impact.get(severity, 1000) * (1 + num_assets * 0.1)
        
        return f"${impact:,.0f} - ${impact * 2:,.0f} (estimated)"
    
    def _assess_reputation_impact(self, severity: str) -> str:
        """Assess reputation impact"""
        reputation_map = {
            'CRITICAL': 'Severe - Public disclosure likely',
            'HIGH': 'Significant - Customer impact',
            'MEDIUM': 'Moderate - Internal impact',
            'LOW': 'Minimal - No external visibility'
        }
        return reputation_map.get(severity, 'Unknown')
    
    def _analyze_patterns(self, log_data: str) -> Dict[str, Any]:
        """Analyze patterns in log data"""
        if not log_data:
            return {}
        
        patterns = {
            'request_rate': self._calculate_request_rate(log_data),
            'peak_time': self._identify_peak_time(log_data),
            'common_targets': self._identify_targets(log_data),
            'anomalies': self._detect_anomalies(log_data)
        }
        
        return patterns
    
    def _calculate_request_rate(self, log_data: str) -> str:
        """Calculate approximate request rate"""
        lines = log_data.split('\n')
        if len(lines) < 2:
            return "Unknown"
        
        # Rough estimate based on log lines
        return f"~{len(lines) * 10} requests/minute (estimated)"
    
    def _identify_peak_time(self, log_data: str) -> str:
        """Identify peak attack time"""
        # Extract timestamps and find most common hour
        time_pattern = r'(\d{2}:\d{2})'
        times = re.findall(time_pattern, log_data)
        
        if times:
            return f"Peak around {times[0]}"
        return "Unknown"
    
    def _identify_targets(self, log_data: str) -> List[str]:
        """Identify common attack targets"""
        targets = []
        
        # Look for URLs, IPs, services
        url_pattern = r'(GET|POST)\s+([^\s]+)'
        urls = re.findall(url_pattern, log_data)
        
        if urls:
            targets = [url[1] for url in urls[:5]]
        
        return targets if targets else ['Unknown']
    
    def _detect_anomalies(self, log_data: str) -> List[str]:
        """Detect anomalies in logs"""
        anomalies = []
        
        # Check for unusual patterns
        if 'error' in log_data.lower():
            anomalies.append("High error rate detected")
        
        if len(log_data.split('\n')) > 100:
            anomalies.append("Abnormally high log volume")
        
        # Check for suspicious patterns
        if re.search(r'(union|select|drop|insert)', log_data.lower()):
            anomalies.append("SQL injection patterns detected")
        
        if re.search(r'(<script|javascript:)', log_data.lower()):
            anomalies.append("XSS patterns detected")
        
        return anomalies if anomalies else ["No significant anomalies"]
    
    def _identify_root_cause(
        self,
        incident_data: Dict,
        patterns: Dict,
        attack_vector: Dict
    ) -> Dict[str, Any]:
        """Identify root cause of incident"""
        attack_type = incident_data.get('attack_type')
        
        root_causes = {
            'DDOS': 'Lack of DDoS protection / rate limiting',
            'BRUTE_FORCE': 'Weak authentication mechanisms / no account lockout',
            'SQL_INJECTION': 'Insufficient input validation / parameterized queries',
            'XSS': 'Inadequate output encoding / CSP not implemented',
            'PORT_SCAN': 'Exposed services / lack of network segmentation'
        }
        
        return {
            'primary_cause': root_causes.get(attack_type, 'Unknown vulnerability'),
            'contributing_factors': [
                'Inadequate monitoring',
                'Delayed response time',
                'Insufficient security controls'
            ],
            'vulnerability_type': self._classify_vulnerability(attack_type)
        }
    
    def _classify_vulnerability(self, attack_type: str) -> str:
        """Classify vulnerability type"""
        vuln_map = {
            'DDOS': 'Infrastructure / Availability',
            'DOS': 'Infrastructure / Availability',
            'BRUTE_FORCE': 'Authentication / Access Control',
            'SQL_INJECTION': 'Input Validation / Injection',
            'XSS': 'Input Validation / Injection',
            'PORT_SCAN': 'Network / Information Disclosure'
        }
        return vuln_map.get(attack_type, 'Unknown')
    
    def _llm_deep_analysis(
        self,
        incident_data: Dict,
        containment_data: Dict,
        attack_vector: Dict,
        log_data: Optional[str]
    ) -> Optional[Dict]:
        """Deep analysis using LLM"""
        try:
            prompt = f"""
Perform deep analysis of this security incident:

Incident Details:
{json.dumps(incident_data, indent=2, default=str)}

Attack Vector:
{json.dumps(attack_vector, indent=2)}

Containment Actions:
{json.dumps(containment_data, indent=2, default=str)}

Provide:
1. Detailed attack flow analysis
2. Hidden risks and concerns
3. Potential secondary attacks
4. Long-term security implications
5. Advanced mitigation strategies

Return structured analysis.
"""
            response = self.llm_engine.generate_response(
                prompt,
                system_prompt="You are a senior security analyst with 15+ years experience."
            )
            
            return {'deep_analysis': response}
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_next_steps(
        self,
        root_cause: Dict,
        impact: Dict
    ) -> List[str]:
        """Generate recommended next steps"""
        steps = [
            "Proceed to Phase 4: Eradication",
            f"Address root cause: {root_cause.get('primary_cause')}",
            "Conduct vulnerability assessment",
            "Update security policies",
            "Review incident response procedures"
        ]
        
        if impact.get('data_breach_risk', '').startswith('HIGH'):
            steps.insert(1, "🚨 Investigate potential data breach immediately")
        
        return steps
    
    def _print_results(self, results: Dict):
        """Pretty print analysis results"""
        print(f"\n{'─'*60}")
        print(f"🆔 Incident ID: {results['incident_id']}")
        print(f"⏰ Timestamp: {results['timestamp']}")
        print(f"{'─'*60}")
        
        # Attack Vector
        av = results['attack_vector']
        print(f"\n🎯 Attack Vector:")
        print(f"  • Type: {av['attack_type']}")
        print(f"  • Sophistication: {av['sophistication']}")
        print(f"  • Entry Points: {', '.join(av.get('entry_points', ['Unknown']))}")
        
        # Timeline
        print(f"\n⏱️  Timeline:")
        for event in results['timeline'][-3:]:
            print(f"  • {event['timestamp']}: {event['event']}")
        
        # Source Analysis
        sa = results['source_analysis']
        print(f"\n🌐 Source Analysis:")
        print(f"  • Total IPs: {sa['total_ips']}")
        print(f"  • Assessment: {sa['threat_intelligence'][0]}")
        
        # Impact Assessment
        impact = results['impact_assessment']
        print(f"\n💥 Impact Assessment:")
        print(f"  • Severity: {impact['severity']}")
        print(f"  • Service Disruption: {impact['service_disruption']}")
        print(f"  • Financial Impact: {impact['financial_impact']}")
        
        # Root Cause
        rc = results['root_cause']
        print(f"\n🔍 Root Cause:")
        print(f"  • Primary: {rc['primary_cause']}")
        print(f"  • Type: {rc['vulnerability_type']}")
        
        print(f"\n{'─'*60}")
        print("✓ Phase 3 Complete - Analysis Done")
        print("─"*60 + "\n")


# Example usage
if __name__ == "__main__":
    # Test data
    sample_incident = {
        'incident_id': 'INC-20260128-103045',
        'timestamp': datetime.now().isoformat(),
        'attack_type': 'DDOS',
        'severity': 'CRITICAL',
        'source_ips': ['45.67.89.123', '103.45.67.89'] + [f"192.168.{i}.{j}" for i in range(1, 10) for j in range(1, 10)],
        'affected_assets': ['web-server-01', 'web-server-02']
    }
    
    sample_containment = {
        'timestamp': datetime.now().isoformat(),
        'blocked_count': 81,
        'execution_status': 'SUCCESS'
    }
    
    analyzer = IncidentAnalysis()
    results = analyzer.analyze(sample_incident, sample_containment)
    
    print("\n📋 Full Results:")
    print(json.dumps(results, indent=2, default=str))

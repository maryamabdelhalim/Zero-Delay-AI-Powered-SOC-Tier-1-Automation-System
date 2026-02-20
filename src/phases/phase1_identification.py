"""
Phase 1: Identification - التعرّف على الحادث الأمني
Identify and classify security incidents
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import re


class IncidentIdentification:
    """
    المرحلة الأولى: التعرف على الحادث
    Phase 1: Incident Identification
    """
    
    # Attack signatures and patterns
    ATTACK_SIGNATURES = {
        'ddos': [
            r'high traffic',
            r'flood',
            r'connection attempts.*(\d{3,})',
            r'syn.*flood',
            r'udp.*flood'
        ],
        'dos': [
            r'denial of service',
            r'resource exhaustion',
            r'cpu.*100%',
            r'memory.*full'
        ],
        'brute_force': [
            r'failed login.*(\d+)',
            r'authentication.*failed',
            r'invalid.*password',
            r'multiple.*attempts'
        ],
        'sql_injection': [
            r"'.*or.*'1'.*=.*'1",
            r'union.*select',
            r'drop.*table',
            r'sql.*injection'
        ],
        'xss': [
            r'<script>',
            r'javascript:',
            r'onerror.*=',
            r'cross.*site.*script'
        ],
        'port_scan': [
            r'port.*scan',
            r'nmap',
            r'scanning.*ports',
            r'probe.*detected'
        ],
        'malware': [
            r'virus.*detected',
            r'malware',
            r'trojan',
            r'ransomware'
        ]
    }
    
    # Severity calculation weights
    SEVERITY_WEIGHTS = {
        'traffic_volume': 0.3,
        'affected_assets': 0.3,
        'attack_sophistication': 0.2,
        'business_impact': 0.2
    }
    
    def __init__(self, llm_engine=None):
        """Initialize Identification module"""
        self.llm_engine = llm_engine
        
    def identify(self, log_data: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Main identification function
        
        Args:
            log_data: Raw security logs
            metadata: Additional metadata
            
        Returns:
            Identification results
        """
        print("\n" + "="*60)
        print("🔍 Phase 1: IDENTIFICATION")
        print("="*60)
        
        # Step 1: Pattern matching for quick classification
        pattern_results = self._pattern_matching(log_data)
        
        # Step 2: Extract key indicators
        indicators = self._extract_indicators(log_data)
        
        # Step 3: Calculate severity
        severity = self._calculate_severity(pattern_results, indicators, log_data)
        
        # Step 4: LLM-based deep analysis (if available)
        if self.llm_engine:
            llm_analysis = self._llm_analysis(log_data, pattern_results)
        else:
            llm_analysis = None
        
        # Step 5: Compile results
        results = {
            'incident_id': self._generate_incident_id(),
            'timestamp': datetime.now().isoformat(),
            'confirmed': pattern_results['attack_detected'],
            'attack_type': pattern_results['attack_type'],
            'confidence': pattern_results['confidence'],
            'severity': severity['level'],
            'severity_score': severity['score'],
            'indicators': indicators,
            'affected_assets': self._identify_affected_assets(log_data),
            'source_ips': indicators.get('ips', []),
            'target_ports': indicators.get('ports', []),
            'llm_insights': llm_analysis,
            'recommendations': self._generate_recommendations(pattern_results, severity)
        }
        
        self._print_results(results)
        
        return results
    
    def _pattern_matching(self, log_data: str) -> Dict[str, Any]:
        """Pattern-based attack detection"""
        log_lower = log_data.lower()
        matches = {}
        
        for attack_type, patterns in self.ATTACK_SIGNATURES.items():
            match_count = 0
            for pattern in patterns:
                if re.search(pattern, log_lower):
                    match_count += 1
            matches[attack_type] = match_count
        
        # Determine most likely attack type
        if matches:
            max_matches = max(matches.values())
            if max_matches > 0:
                attack_type = max(matches, key=matches.get)
                confidence = min(0.95, (max_matches / len(self.ATTACK_SIGNATURES[attack_type])))
                return {
                    'attack_detected': True,
                    'attack_type': attack_type.upper(),
                    'confidence': round(confidence, 2),
                    'matches': matches
                }
        
        return {
            'attack_detected': False,
            'attack_type': 'UNKNOWN',
            'confidence': 0.0,
            'matches': matches
        }
    
    def _extract_indicators(self, log_data: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise (IOCs)"""
        indicators = {
            'ips': [],
            'ports': [],
            'urls': [],
            'domains': []
        }
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        indicators['ips'] = list(set(re.findall(ip_pattern, log_data)))
        
        # Extract ports
        port_pattern = r':(\d{1,5})\b'
        potential_ports = re.findall(port_pattern, log_data)
        indicators['ports'] = [p for p in set(potential_ports) if 0 < int(p) <= 65535]
        
        # Extract URLs
        url_pattern = r'https?://[^\s]+'
        indicators['urls'] = list(set(re.findall(url_pattern, log_data)))
        
        # Extract domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        indicators['domains'] = list(set(re.findall(domain_pattern, log_data.lower())))
        
        return indicators
    
    def _calculate_severity(
        self, 
        pattern_results: Dict, 
        indicators: Dict,
        log_data: str
    ) -> Dict[str, Any]:
        """Calculate incident severity"""
        score = 0.0
        
        # Factor 1: Attack type severity
        attack_severity_map = {
            'DDOS': 0.9,
            'DOS': 0.8,
            'SQL_INJECTION': 0.85,
            'BRUTE_FORCE': 0.6,
            'XSS': 0.7,
            'PORT_SCAN': 0.4,
            'MALWARE': 0.95,
            'UNKNOWN': 0.5
        }
        
        attack_type = pattern_results.get('attack_type', 'UNKNOWN')
        score += attack_severity_map.get(attack_type, 0.5) * self.SEVERITY_WEIGHTS['traffic_volume']
        
        # Factor 2: Number of affected IPs
        num_ips = len(indicators.get('ips', []))
        ip_score = min(1.0, num_ips / 10)
        score += ip_score * self.SEVERITY_WEIGHTS['affected_assets']
        
        # Factor 3: Confidence level
        confidence = pattern_results.get('confidence', 0.0)
        score += confidence * self.SEVERITY_WEIGHTS['attack_sophistication']
        
        # Factor 4: Log volume (as proxy for impact)
        log_lines = len(log_data.split('\n'))
        volume_score = min(1.0, log_lines / 100)
        score += volume_score * self.SEVERITY_WEIGHTS['business_impact']
        
        # Determine severity level
        if score >= 0.8:
            level = "CRITICAL"
        elif score >= 0.6:
            level = "HIGH"
        elif score >= 0.4:
            level = "MEDIUM"
        else:
            level = "LOW"
        
        return {
            'score': round(score, 2),
            'level': level
        }
    
    def _identify_affected_assets(self, log_data: str) -> List[str]:
        """Identify affected systems/assets"""
        assets = []
        
        # Common asset naming patterns
        asset_patterns = [
            r'(web-server-\d+)',
            r'(db-server-\d+)',
            r'(app-server-\d+)',
            r'(server-\d+)',
            r'(host-\d+)',
            r'192\.168\.\d+\.\d+'
        ]
        
        for pattern in asset_patterns:
            matches = re.findall(pattern, log_data, re.IGNORECASE)
            assets.extend(matches)
        
        return list(set(assets))
    
    def _llm_analysis(self, log_data: str, pattern_results: Dict) -> Optional[Dict]:
        """Deep analysis using LLM"""
        try:
            prompt = f"""
Analyze this security incident log:

{log_data[:1000]}  # Limit to first 1000 chars

Initial Classification: {pattern_results['attack_type']}
Confidence: {pattern_results['confidence']}

Provide:
1. Confirmation of attack type
2. Additional insights
3. Hidden patterns
4. Risk assessment

Return in JSON format.
"""
            response = self.llm_engine.generate_response(
                prompt,
                system_prompt="You are a SOC analyst. Analyze security incidents."
            )
            
            return {'analysis': response}
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        now = datetime.now()
        return f"INC-{now.strftime('%Y%m%d-%H%M%S')}"
    
    def _generate_recommendations(
        self, 
        pattern_results: Dict, 
        severity: Dict
    ) -> List[str]:
        """Generate immediate action recommendations"""
        recommendations = []
        attack_type = pattern_results.get('attack_type', 'UNKNOWN')
        severity_level = severity.get('level', 'LOW')
        
        # Critical severity actions
        if severity_level == "CRITICAL":
            recommendations.append("🚨 Immediate escalation to SOC Tier 2 required")
            recommendations.append("🚨 Consider activating incident response team")
        
        # Attack-specific recommendations
        if attack_type == "DDOS":
            recommendations.extend([
                "Enable rate limiting immediately",
                "Activate DDoS mitigation service",
                "Identify and block source IPs"
            ])
        elif attack_type == "BRUTE_FORCE":
            recommendations.extend([
                "Lock affected user accounts",
                "Implement account lockout policies",
                "Enable MFA if not already active"
            ])
        elif attack_type == "SQL_INJECTION":
            recommendations.extend([
                "Isolate affected database servers",
                "Review and patch SQL vulnerabilities",
                "Check for data exfiltration"
            ])
        
        # General recommendations
        recommendations.extend([
            "Proceed to Phase 2: Containment",
            "Document all findings",
            "Notify relevant stakeholders"
        ])
        
        return recommendations
    
    def _print_results(self, results: Dict):
        """Pretty print identification results"""
        print(f"\n{'─'*60}")
        print(f"🆔 Incident ID: {results['incident_id']}")
        print(f"⏰ Timestamp: {results['timestamp']}")
        print(f"{'─'*60}")
        
        print(f"\n✅ Attack Confirmed: {results['confirmed']}")
        print(f"🎯 Attack Type: {results['attack_type']}")
        print(f"📊 Confidence: {results['confidence']*100:.0f}%")
        print(f"⚠️  Severity: {results['severity']} ({results['severity_score']})")
        
        print(f"\n🎯 Affected Assets:")
        for asset in results['affected_assets'][:5]:
            print(f"  • {asset}")
        
        print(f"\n🌐 Source IPs:")
        for ip in results['source_ips'][:5]:
            print(f"  • {ip}")
        
        print(f"\n💡 Immediate Recommendations:")
        for rec in results['recommendations'][:5]:
            print(f"  • {rec}")
        
        print(f"\n{'─'*60}")
        print("✓ Phase 1 Complete - Ready for Containment")
        print("─"*60 + "\n")


# Example usage
if __name__ == "__main__":
    # Test with sample log
    sample_log = """
2026-01-28 10:30:45 FIREWALL ALERT: High traffic detected
2026-01-28 10:30:46 Source IP: 45.67.89.123 - 1500 requests/sec
2026-01-28 10:30:47 Target: web-server-01 (192.168.1.100:80)
2026-01-28 10:30:48 Pattern: SYN flood attack detected
2026-01-28 10:30:49 Additional sources: 103.45.67.89, 78.23.45.67
2026-01-28 10:30:50 Total requests: 15,000 in last 10 seconds
"""
    
    identifier = IncidentIdentification()
    results = identifier.identify(sample_log)
    
    print("\n📋 Full Results:")
    print(json.dumps(results, indent=2, default=str))

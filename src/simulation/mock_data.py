"""
Simulation System - Mock Data Generator
Generate realistic attack scenarios for testing
"""

from typing import Dict, List
from datetime import datetime, timedelta
import random


class AttackSimulator:
    """Generate realistic attack scenarios for testing"""
    
    ATTACK_TYPES = [
        'ddos', 'dos', 'brute_force',
        'sql_injection', 'xss', 'port_scan'
    ]
    
    def __init__(self):
        self.malicious_ips = self._generate_malicious_ips()
        
    def generate_attack(self, attack_type: str = None) -> Dict:
        """Generate a simulated attack scenario"""
        if attack_type is None:
            attack_type = random.choice(self.ATTACK_TYPES)
        
        attack_type = attack_type.lower()
        
        generators = {
            'ddos': self._generate_ddos,
            'dos': self._generate_dos,
            'brute_force': self._generate_brute_force,
            'sql_injection': self._generate_sql_injection,
            'xss': self._generate_xss,
            'port_scan': self._generate_port_scan
        }
        
        generator = generators.get(attack_type, self._generate_ddos)
        return generator()
    
    def _generate_malicious_ips(self, count: int = 100) -> List[str]:
        """Generate list of fake malicious IPs"""
        ips = []
        for _ in range(count):
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    def _generate_ddos(self) -> Dict:
        """Generate DDoS attack scenario"""
        num_ips = random.randint(50, 150)
        source_ips = random.sample(self.malicious_ips, min(num_ips, len(self.malicious_ips)))
        
        log_entries = []
        base_time = datetime.now() - timedelta(minutes=30)
        
        for i in range(100):
            timestamp = (base_time + timedelta(seconds=i*3)).strftime('%Y-%m-%d %H:%M:%S')
            ip = random.choice(source_ips)
            log_entries.append(
                f"{timestamp} FIREWALL ALERT: High traffic from {ip}"
            )
            log_entries.append(
                f"{timestamp} Connection attempts: {random.randint(500, 2000)} req/sec"
            )
        
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Target: web-server-01 (192.168.1.100:80)")
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Pattern: SYN flood attack detected")
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Total requests: {random.randint(50000, 150000)} in last 10 minutes")
        
        return {
            'attack_type': 'ddos',
            'logs': '\n'.join(log_entries),
            'metadata': {
                'source_ips': source_ips,
                'target': 'web-server-01',
                'duration': '30 minutes',
                'severity': 'CRITICAL'
            }
        }
    
    def _generate_dos(self) -> Dict:
        """Generate DoS attack scenario"""
        source_ip = random.choice(self.malicious_ips)
        
        log_entries = []
        base_time = datetime.now() - timedelta(minutes=15)
        
        for i in range(50):
            timestamp = (base_time + timedelta(seconds=i*5)).strftime('%Y-%m-%d %H:%M:%S')
            log_entries.append(
                f"{timestamp} SERVER WARNING: Resource exhaustion detected"
            )
            log_entries.append(
                f"{timestamp} Source: {source_ip} - {random.randint(100, 500)} req/sec"
            )
        
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} CPU usage: {random.randint(85, 99)}%")
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Memory: {random.randint(90, 99)}% full")
        
        return {
            'attack_type': 'dos',
            'logs': '\n'.join(log_entries),
            'metadata': {
                'source_ips': [source_ip],
                'target': 'web-server-01',
                'duration': '15 minutes',
                'severity': 'HIGH'
            }
        }
    
    def _generate_brute_force(self) -> Dict:
        """Generate brute force attack scenario"""
        source_ips = random.sample(self.malicious_ips, random.randint(3, 10))
        
        log_entries = []
        base_time = datetime.now() - timedelta(minutes=20)
        
        usernames = ['admin', 'root', 'user', 'test', 'administrator']
        
        for i in range(80):
            timestamp = (base_time + timedelta(seconds=i*10)).strftime('%Y-%m-%d %H:%M:%S')
            ip = random.choice(source_ips)
            user = random.choice(usernames)
            log_entries.append(
                f"{timestamp} AUTH FAILURE: User '{user}' from {ip} - Invalid password"
            )
        
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} SECURITY ALERT: Multiple failed login attempts detected")
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Total failed attempts: {random.randint(500, 2000)} in last 20 minutes")
        
        return {
            'attack_type': 'brute_force',
            'logs': '\n'.join(log_entries),
            'metadata': {
                'source_ips': source_ips,
                'target': 'ssh-server',
                'duration': '20 minutes',
                'severity': 'HIGH'
            }
        }
    
    def _generate_sql_injection(self) -> Dict:
        """Generate SQL injection attack scenario"""
        source_ips = random.sample(self.malicious_ips, random.randint(1, 5))
        
        log_entries = []
        base_time = datetime.now() - timedelta(minutes=10)
        
        sql_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM passwords--",
            "admin'--",
            "' OR 1=1--"
        ]
        
        for i in range(30):
            timestamp = (base_time + timedelta(seconds=i*15)).strftime('%Y-%m-%d %H:%M:%S')
            ip = random.choice(source_ips)
            pattern = random.choice(sql_patterns)
            log_entries.append(
                f"{timestamp} WEB SERVER: Suspicious query from {ip}"
            )
            log_entries.append(
                f"{timestamp} Query contains: {pattern}"
            )
        
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} SQL INJECTION DETECTED")
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Target: /login.php, /search.php")
        
        return {
            'attack_type': 'sql_injection',
            'logs': '\n'.join(log_entries),
            'metadata': {
                'source_ips': source_ips,
                'target': 'web-application',
                'duration': '10 minutes',
                'severity': 'CRITICAL'
            }
        }
    
    def _generate_xss(self) -> Dict:
        """Generate XSS attack scenario"""
        source_ips = random.sample(self.malicious_ips, random.randint(1, 3))
        
        log_entries = []
        base_time = datetime.now() - timedelta(minutes=5)
        
        xss_patterns = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        for i in range(20):
            timestamp = (base_time + timedelta(seconds=i*10)).strftime('%Y-%m-%d %H:%M:%S')
            ip = random.choice(source_ips)
            pattern = random.choice(xss_patterns)
            log_entries.append(
                f"{timestamp} WEB SERVER: Malicious input from {ip}"
            )
            log_entries.append(
                f"{timestamp} Detected pattern: {pattern}"
            )
        
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} CROSS-SITE SCRIPTING ATTEMPT")
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Target: /comment.php, /profile.php")
        
        return {
            'attack_type': 'xss',
            'logs': '\n'.join(log_entries),
            'metadata': {
                'source_ips': source_ips,
                'target': 'web-application',
                'duration': '5 minutes',
                'severity': 'HIGH'
            }
        }
    
    def _generate_port_scan(self) -> Dict:
        """Generate port scan attack scenario"""
        source_ip = random.choice(self.malicious_ips)
        
        log_entries = []
        base_time = datetime.now() - timedelta(minutes=3)
        
        ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
        
        for i, port in enumerate(ports):
            timestamp = (base_time + timedelta(seconds=i*5)).strftime('%Y-%m-%d %H:%M:%S')
            log_entries.append(
                f"{timestamp} FIREWALL: Connection attempt from {source_ip} to port {port}"
            )
            log_entries.append(
                f"{timestamp} Probe detected on port {port}"
            )
        
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} PORT SCAN DETECTED")
        log_entries.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Scanning {len(ports)} ports from {source_ip}")
        
        return {
            'attack_type': 'port_scan',
            'logs': '\n'.join(log_entries),
            'metadata': {
                'source_ips': [source_ip],
                'target': '192.168.1.0/24',
                'duration': '3 minutes',
                'severity': 'MEDIUM'
            }
        }


# Example usage
if __name__ == "__main__":
    simulator = AttackSimulator()
    
    print("🎭 Attack Simulator - Demo\n")
    
    for attack_type in ['ddos', 'brute_force', 'sql_injection']:
        print(f"\n{'='*60}")
        print(f"Simulating: {attack_type.upper()}")
        print("="*60)
        
        attack = simulator.generate_attack(attack_type)
        
        print(f"\nMetadata: {attack['metadata']}")
        print(f"\nSample Logs (first 500 chars):")
        print(attack['logs'][:500])
        print("...")

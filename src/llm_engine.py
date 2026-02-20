"""
LLM Engine - Core AI Component for SOC Automation
"""

import os
import yaml
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import json

try:
    import ollama
except ImportError:
    print("⚠️  Warning: ollama package not installed. Install with: pip install ollama")
    ollama = None


@dataclass
class LLMConfig:
    """LLM Configuration"""
    provider: str = "ollama"
    model: str = "llama3.2"
    temperature: float = 0.7
    max_tokens: int = 2000
    timeout: int = 60
    base_url: str = "http://localhost:11434"


class LLMEngine:
    """
    محرك الذكاء الاصطناعي الرئيسي
    Main AI Engine for SOC Automation
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize LLM Engine"""
        self.config = self._load_config(config_path)
        self.llm_config = self._parse_llm_config()
        self.conversation_history: List[Dict] = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"⚠️  Config file not found: {config_path}, using defaults")
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            'llm': {
                'provider': 'ollama',
                'model': 'llama3.2',
                'temperature': 0.7,
                'max_tokens': 2000,
                'timeout': 60,
                'base_url': 'http://localhost:11434'
            }
        }
    
    def _parse_llm_config(self) -> LLMConfig:
        """Parse LLM configuration"""
        llm_cfg = self.config.get('llm', {})
        return LLMConfig(
            provider=llm_cfg.get('provider', 'ollama'),
            model=llm_cfg.get('model', 'llama3.2'),
            temperature=llm_cfg.get('temperature', 0.7),
            max_tokens=llm_cfg.get('max_tokens', 2000),
            timeout=llm_cfg.get('timeout', 60),
            base_url=llm_cfg.get('base_url', 'http://localhost:11434')
        )
    
    def generate_response(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None,
        context: Optional[Dict] = None,
        stream: bool = False
    ) -> str:
        """
        Generate response from LLM
        
        Args:
            prompt: User prompt
            system_prompt: System instructions
            context: Additional context
            stream: Stream response
            
        Returns:
            Generated response
        """
        if ollama is None:
            return self._fallback_response(prompt)
        
        try:
            # Prepare messages
            messages = []
            
            if system_prompt:
                messages.append({
                    "role": "system",
                    "content": system_prompt
                })
            
            # Add context if provided
            if context:
                context_str = f"\n\nContext:\n{json.dumps(context, indent=2)}"
                prompt = prompt + context_str
            
            messages.append({
                "role": "user",
                "content": prompt
            })
            
            # Generate response
            response = ollama.chat(
                model=self.llm_config.model,
                messages=messages,
                options={
                    "temperature": self.llm_config.temperature,
                    "num_predict": self.llm_config.max_tokens,
                }
            )
            
            return response['message']['content']
            
        except Exception as e:
            print(f"❌ Error generating response: {e}")
            return self._fallback_response(prompt)
    
    def _fallback_response(self, prompt: str) -> str:
        """Fallback response when LLM is not available"""
        return """
⚠️  LLM Engine is not available. Please ensure:
1. Ollama is installed: https://ollama.com/download
2. Ollama is running: ollama serve
3. Model is downloaded: ollama pull llama3.2

For now, returning template response.
"""
    
    def analyze_incident(
        self, 
        log_data: str, 
        attack_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze security incident using LLM
        
        Args:
            log_data: Raw log data
            attack_type: Known attack type (optional)
            
        Returns:
            Analysis results
        """
        system_prompt = """You are an expert SOC Tier 1 analyst specializing in cybersecurity incident response.
Your task is to analyze security logs and incidents following the 5-phase incident response framework:
1. Identification
2. Containment
3. Analysis
4. Eradication
5. Recovery

Provide detailed, actionable insights in JSON format."""

        prompt = f"""
Analyze the following security incident:

Attack Type: {attack_type or 'Unknown'}

Log Data:
```
{log_data}
```

Please provide:
1. Incident classification and severity
2. Affected assets
3. Attack indicators (IPs, ports, patterns)
4. Recommended containment actions
5. Analysis of attack vector
6. Eradication steps
7. Recovery recommendations

Return results in JSON format with clear structure.
"""
        
        response = self.generate_response(prompt, system_prompt)
        
        try:
            # Try to parse JSON response
            return json.loads(response)
        except json.JSONDecodeError:
            # If not JSON, return structured text
            return {
                "raw_analysis": response,
                "format": "text"
            }
    
    def generate_firewall_rules(self, malicious_ips: List[str]) -> List[str]:
        """Generate firewall rules for blocking IPs"""
        system_prompt = "You are a firewall configuration expert. Generate blocking rules for given IP addresses."
        
        prompt = f"""
Generate firewall blocking rules for the following malicious IP addresses:
{', '.join(malicious_ips)}

Provide rules in multiple formats:
1. iptables (Linux)
2. pfSense
3. Cisco ASA
4. Palo Alto

Format as clear, copy-paste ready commands.
"""
        
        response = self.generate_response(prompt, system_prompt)
        return response.split('\n')
    
    def create_incident_report(self, incident_data: Dict) -> str:
        """Create comprehensive incident report"""
        system_prompt = "You are a security report writer. Create professional incident reports."
        
        prompt = f"""
Create a comprehensive incident report based on the following data:

{json.dumps(incident_data, indent=2)}

The report should include:
1. Executive Summary
2. Incident Timeline
3. Technical Details
4. Actions Taken
5. Recommendations
6. Lessons Learned

Format in professional Markdown.
"""
        
        return self.generate_response(prompt, system_prompt)
    
    def suggest_containment_actions(
        self, 
        attack_type: str, 
        severity: str,
        affected_assets: List[str]
    ) -> List[str]:
        """Suggest containment actions based on incident"""
        system_prompt = "You are a SOC incident response expert. Suggest immediate containment actions."
        
        prompt = f"""
Incident Details:
- Attack Type: {attack_type}
- Severity: {severity}
- Affected Assets: {', '.join(affected_assets)}

Suggest immediate containment actions prioritized by urgency.
Return as numbered list with clear, actionable steps.
"""
        
        response = self.generate_response(prompt, system_prompt)
        return [line.strip() for line in response.split('\n') if line.strip()]
    
    def health_check(self) -> bool:
        """Check if LLM engine is healthy and responsive"""
        try:
            if ollama is None:
                return False
            
            response = ollama.chat(
                model=self.llm_config.model,
                messages=[{"role": "user", "content": "ping"}]
            )
            return True
        except Exception as e:
            print(f"❌ Health check failed: {e}")
            return False


# Example usage
if __name__ == "__main__":
    engine = LLMEngine()
    
    # Test health check
    if engine.health_check():
        print("✅ LLM Engine is healthy!")
        
        # Test analysis
        sample_log = """
        2026-01-28 10:30:45 FIREWALL ALERT: High traffic from 45.67.89.123
        2026-01-28 10:30:46 Multiple connection attempts: 1500 req/sec
        2026-01-28 10:30:47 Target: web-server-01 (192.168.1.100)
        """
        
        result = engine.analyze_incident(sample_log, "DDoS")
        print("\n📊 Analysis Result:")
        print(json.dumps(result, indent=2))
    else:
        print("❌ LLM Engine is not available")
        print("Please install and run Ollama: https://ollama.com")

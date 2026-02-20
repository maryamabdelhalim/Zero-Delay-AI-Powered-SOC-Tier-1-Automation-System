🛡️ SOC Tier 1 Automation System

An AI-powered platform designed to automate Security Operations Center (SOC) Tier 1 incident response workflows using a free, locally deployed Large Language Model (LLM).

🌟 Features

✅ Fully Free – Powered by Ollama + Llama 3.2

✅ Complete Five-Phase Incident Response Framework

✅ Professional CLI Interface built with Rich

✅ Built-in Simulation Environment for testing and training

✅ Automated Structured Reporting

✅ Local Deployment – No internet connection required

📋 Requirements
1. Python 3.9+
python --version
2. Ollama (for Local LLM)
# Linux/Mac
curl -fsSL https://ollama.com/install.sh | sh

# Windows
Download from: https://ollama.com/download
3. Download Llama 3.2 Model
ollama pull llama3.2
🚀 Quick Installation
Step 1: Clone the Repository
git clone <repo-url>
cd soc_automation_project
Step 2: Create a Virtual Environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows
Step 3: Install Dependencies
pip install -r requirements.txt
Step 4: Test the System
python main.py --help
🎮 Usage
1️⃣ Run a Simulated Incident (Demo)
python main.py simulate --attack-type ddos
2️⃣ Analyze a Real Log File
python main.py analyze --log-file /path/to/firewall.log
3️⃣ View Previous Reports
python main.py reports --list
4️⃣ Interactive Mode
python main.py interactive
🏗️ Project Structure
soc_automation_project/
├── main.py                 # Main entry point
├── requirements.txt        # Required dependencies
├── README.md               # This file
├── config/
│   └── config.yaml         # System configuration
├── src/
│   ├── __init__.py
│   ├── llm_engine.py       # LLM engine
│   ├── phases/
│   │   ├── __init__.py
│   │   ├── phase1_identification.py
│   │   ├── phase2_containment.py
│   │   ├── phase3_analysis.py
│   │   ├── phase4_eradication.py
│   │   └── phase5_recovery.py
│   ├── cli/
│   │   ├── __init__.py
│   │   └── interface.py    # CLI interface
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── logger.py
│   │   └── report_generator.py
│   └── simulation/
│       ├── __init__.py
│       └── mock_data.py    # Simulated data
├── data/
│   ├── logs/               # Simulated logs
│   └── reports/            # Generated reports
└── database/
    └── incidents.db        # Incident database


    
🔄 Five Incident Response Phases
1️⃣ Identification

Automated log analysis

Attack type classification

Severity assessment

2️⃣ Containment

Firewall rule generation

IP blocking recommendations

Rate limiting activation

3️⃣ Analysis

Attack vector analysis

Source identification

Attack timeline reconstruction

4️⃣ Eradication

Backdoor removal recommendations

Security policy updates

Hardening recommendations

5️⃣ Recovery

Service restoration plan

Monitoring plan

Final structured incident report

📊 Example Output
SOC Tier 1 Automation - Incident Report

Incident ID: INC-2026-001
Timestamp: 2026-01-28 10:30:45

Phase 1: IDENTIFICATION
Attack Type: DDoS
Severity: CRITICAL
Affected Assets: web-server-01, web-server-02
Source IPs: 45.67.89.*, 192.168.*.*

Phase 2: CONTAINMENT
Actions Taken:
✓ Blocked 127 malicious IPs
✓ Rate limiting enabled (100 req/min)
✓ WAF rules updated

... (remaining phases)
⚙️ Configuration

Modify settings inside config/config.yaml:

llm:
  model: "llama3.2"
  temperature: 0.7
  max_tokens: 2000

detection:
  threshold: 0.8
  auto_containment: false

reporting:
  format: "markdown"  # or "json" or "html"
  auto_save: true
🔐 Security

✅ All data processed locally

✅ No external data transmission

✅ Encrypted logs

✅ Customizable access control

🚧 Roadmap

 Support for multiple LLM models

 Web dashboard

 Real SIEM integration

 Machine learning enhancements

 API for integration

 Docker containerization

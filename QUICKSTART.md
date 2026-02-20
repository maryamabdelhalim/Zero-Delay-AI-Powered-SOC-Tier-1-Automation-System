# 🚀 Quick Start Guide

## Installation Steps

### Step 1: System Requirements

```bash
# Check Python version (3.9+ required)
python --version

# Check if git is installed
git --version
```

### Step 2: Download Project

```bash
# If you have the project files locally:
cd soc_automation_project

# Or clone from repository:
# git clone <repository-url>
# cd soc_automation_project
```

### Step 3: Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Linux/Mac:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# You should see (venv) in your terminal prompt
```

### Step 4: Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# This will install:
# - FastAPI, Rich, Click (for CLI)
# - LangChain, Ollama (for LLM)
# - Pandas, NumPy (for data processing)
# - And more...
```

### Step 5: Install Ollama (Optional but Recommended)

Ollama provides the local LLM capabilities.

#### Linux/Mac:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

#### Windows:
Download from: https://ollama.com/download

#### Download Llama 3.2 Model:
```bash
# This will download ~2GB
ollama pull llama3.2

# Verify it's working
ollama run llama3.2
# Type "hello" and press Enter
# Type /bye to exit
```

### Step 6: Test Installation

```bash
# Run the system
python main.py --help

# You should see the help menu
```

---

## 🎮 Quick Start - Your First Simulation

### Option 1: Interactive Mode (Recommended for Beginners)

```bash
# Start interactive mode
python main.py

# Or simply:
python main.py interactive

# This will show you a beautiful menu!
```

Then:
1. Select option **1** (Simulate Attack)
2. Choose an attack type (try **DDoS** first)
3. Watch the magic happen! ✨

### Option 2: Command Line Mode

```bash
# Simulate a DDoS attack
python main.py simulate --attack-type ddos

# Simulate a random attack
python main.py simulate

# Analyze a log file
python main.py analyze --log-file /path/to/your/logfile.log
```

---

## 📊 What You'll See

### Phase 1: Identification
```
🔍 Phase 1: IDENTIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Attack Confirmed: True
🎯 Attack Type: DDOS
📊 Confidence: 95%
⚠️  Severity: CRITICAL (0.92)
```

### Phase 2: Containment
```
🛡️  Phase 2: CONTAINMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡ Actions Taken:
  🔴 [ACT-001] Block 127 malicious IPs
  🟡 [ACT-002] Enable aggressive rate limiting
```

### Phase 3: Analysis
```
🔬 Phase 3: ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Attack Vector: DDOS
📊 Sophistication: HIGH
💥 Impact: Complete service outage
```

### Phase 4: Eradication
```
🔧 Phase 4: ERADICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Vulnerabilities Fixed: 2
🔧 Patches Applied: 2
🛡️  Hardening Steps: 5
```

### Phase 5: Recovery
```
🔄 Phase 5: RECOVERY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 Strategy: Phased recovery with extended monitoring
⏳ Duration: 24-48 hours
✅ Services Restored
```

---

## 🎯 Common Use Cases

### Use Case 1: Learning SOC Operations
```bash
# Simulate different attacks to learn
python main.py simulate --attack-type ddos
python main.py simulate --attack-type sql_injection
python main.py simulate --attack-type brute_force
```

### Use Case 2: Testing Your Log Files
```bash
# Analyze your actual firewall logs
python main.py analyze --log-file /var/log/firewall.log

# Analyze Apache/Nginx logs
python main.py analyze --log-file /var/log/nginx/access.log
```

### Use Case 3: Demo for Management
```bash
# Run in interactive mode with nice UI
python main.py interactive

# Select "Simulate Attack"
# Choose "DDoS" for impressive demo
# Watch all 5 phases execute!
```

---

## ⚙️ Configuration

Edit `config/config.yaml` to customize:

```yaml
# LLM Settings
llm:
  model: "llama3.2"
  temperature: 0.7

# Detection Settings
detection:
  threshold: 0.75
  auto_containment: false  # Set true for automatic actions

# Reporting
reporting:
  format: "markdown"
  language: "en"  # or "ar" for Arabic
```

---

## 🐛 Troubleshooting

### Problem: "ollama not found"
**Solution:**
```bash
# Check if Ollama is installed
ollama --version

# If not, install it:
curl -fsSL https://ollama.com/install.sh | sh

# Make sure ollama is running:
ollama serve
```

### Problem: "Module not found"
**Solution:**
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Problem: "Permission denied"
**Solution:**
```bash
# Make main.py executable
chmod +x main.py

# Or run with python explicitly
python main.py
```

### Problem: LLM responses are slow
**Solution:**
- This is normal for local LLMs
- First run downloads the model (~2GB)
- Subsequent runs are faster
- Consider using a machine with more RAM

---

## 📚 Next Steps

1. **Read the full README.md** for detailed documentation
2. **Try all attack types** to see different scenarios
3. **Customize config.yaml** for your environment
4. **Integrate with real systems** (advanced)

---

## 🎓 Learning Resources

### Understanding the 5 Phases:
1. **Identification**: Like a doctor's diagnosis
2. **Containment**: Stop the bleeding first
3. **Analysis**: Understand what happened
4. **Eradication**: Remove the disease
5. **Recovery**: Get back to normal

### Best Practices:
- Always review recommendations before auto-execution
- Keep logs of all incidents
- Update your incident response procedures
- Practice regularly with simulations

---

## 🆘 Getting Help

- Check **README.md** for detailed docs
- Review **config/config.yaml** for settings
- Run with `--help` flag for command help
- Check logs in `logs/` directory

---

## 🎉 Success!

If you see this after running a simulation:

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║               ✅ INCIDENT SUCCESSFULLY RESOLVED ✅            ║
║                                                               ║
║          All 5 phases completed successfully!                ║
║          System returned to normal operation.                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

**Congratulations!** 🎊 Your SOC automation system is working perfectly!

---

## 💡 Pro Tips

1. **Start Simple**: Begin with simulated attacks
2. **Read Logs**: Check `logs/` for detailed execution logs
3. **Experiment**: Try different attack types
4. **Customize**: Adjust thresholds in config.yaml
5. **Integrate**: Connect to your real SIEM/firewall (advanced)

---

**Happy Automating! 🛡️🚀**

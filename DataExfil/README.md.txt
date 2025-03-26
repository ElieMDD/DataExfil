# 🔒 Exfiltration PoC  
*For authorized security research only*  

## ⚠️ Legal Notice  
Unauthorized use violates:  
- Computer Fraud and Abuse Act (CFAA)  
- GDPR and other international laws 

## 🚀 Usage  
```cmd
pip install -r requirements.txt
python exfil_script.py

#### **3. LEGAL.md**
```markdown
# 📜 Legal Terms  
You MUST have:  
✅ Written permission from system owner  
✅ Isolated testing environment  

## 🛡️ Detection Rules (For Defenders)

This project includes detection artifacts to help blue teams identify this activity:

| Rule Type | Purpose | File Location |
|-----------|---------|---------------|
| [Sigma](https://github.com/SigmaHQ/sigma) | SIEM Detection | [`/detection/sigma_rule.yml`](/detection/sigma_rule.yml) |
| [YARA](https://virustotal.github.io/yara/) | Host-Based Detection | [`/detection/yara_rule.yar`](/detection/yara_rule.yar) |
| [Suricata](https://suricata.io/) | Network Detection | [`/detection/suricata.rules`](/detection/suricata.rules) |

**Usage Example** (YARA):
```bash
yara -r detection/yara_rule.yar /path/to/scan
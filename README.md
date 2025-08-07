# Minimal Caldera Lab Automation

Automates Cisco Secure Firewall policy configuration for Caldera lab testing.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run automation
python caldera_automation.py
```

## What You Need

1. **cdFMC URL** (e.g., `https://tenant.us.cdo.cisco.com`)
2. **API Token** (get from CDO: Settings → API Tokens)
3. **Target Device** (usually `NGFW1`)

The script will prompt for these values and optionally save them for future use.

## What It Does

✅ Creates DNS Policy  
✅ Creates File Policy with malware detection  
✅ Creates Intrusion Policy with SnortML  
✅ Configures Access Control Policy  
✅ Deploys to firewall device  

## Files

- `caldera_automation.py` - Main script (handles all configuration)
- `fmc_oas3.json` - API specification  
- `requirements.txt` - Dependencies
- `run.sh` - Simple runner script

Done! 🚀
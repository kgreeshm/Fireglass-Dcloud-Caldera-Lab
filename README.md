# Comprehensive Caldera Lab Automation - Modular Version

**Complete** automation for Cisco Secure Firewall RS25 Caldera New SCC lab with modular design for easy troubleshooting.

## 🚀 Quick Start

```bash
# 1. Configure your credentials
edit inputs.sh

# 2. Run the full automation
./run.sh

# 3. Or run individual modules for troubleshooting
python file_policy.py
python intrusion_policy.py
python access_policy.py
```

## 📋 What You Need

1. **cdFMC URL** (e.g., `https://cisco-yourlab.app.apj.cdo.cisco.com`) 
2. **API Token** (get from CDO: Settings → API Tokens)
3. **Target Device** (keep as `NGFW1` for lab)

Edit these values in `inputs.sh`.

## 🔧 Modular Architecture

### � **file_policy.py** - File Policy Module
- ✅ Creates "File Policy" with exact lab name
- ✅ **Rule 1**: Block file types (REG, TORRENT, PST)
- ✅ **Rule 2**: Block malware (Spero + Dynamic + Local analysis)
- ✅ **Advanced Settings**: Archive inspection enabled

### 🛡️ **intrusion_policy.py** - Intrusion Policy Module  
- ✅ Creates "SnortML" policy with exact lab name
- ✅ **Base Policy**: Balanced Security and Connectivity
- ✅ **Rule 411:1**: SnortML enabled for machine learning detection
- ✅ **Prevention Mode**: Configured correctly

### 🚪 **access_policy.py** - Access Control Policy Module
- ✅ Configures existing "NGFW1 Firewall Policy"
- ✅ **Security Intelligence**: Malicious IPs/URLs blocked
- ✅ **Rule 1**: "Block Unwanted URLs" (Adult, Malware, etc.)
- ✅ **Rule 2**: "Block Unwanted Applications" (High risk, remote desktop)
- ✅ **Rule 3**: "Inspect All" with File + Intrusion policies
- ✅ **Advanced Settings**: DNS reputation + Early detection

### 🎭 **caldera_lab.py** - Main Orchestrator
- 🎯 Coordinates all three modules in sequence
- 📊 Provides comprehensive progress reporting
- 🔗 Links policies together (File + Intrusion → Access)
- ⚡ Optimized execution order

### 📝 DNS Policy (Manual - API limitation)
- 📝 **Manual**: Configure "DNS Policy" in CDO web interface
- 📝 **Rule**: "Block Malicious DNS" with all Talos feeds

## 🎯 Lab Results

After automation + manual DNS policy:
- **Initial Posture**: 0% (all attacks succeed)
- **Final Posture**: 100% (all attacks blocked)

## 📁 Files

- **`caldera_automation.py`** - Complete automation script
- **`inputs.sh`** - Your configuration (edit this!)
- **`run.sh`** - Execution script  
- **`requirements.txt`** - Python dependencies

## 🔧 Usage

```bash
# Edit configuration
nano inputs.sh

# Run automation  
./run.sh

# Manual step: Configure DNS Policy in CDO web interface
# Then run Caldera assessment from WKST1
```

**Result**: Comprehensive security posture achieving 100% threat blocking! �️
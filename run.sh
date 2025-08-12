#!/bin/bash
# Enhanced runner for Caldera Lab Automation with automatic venv management

echo "🚀 Caldera Lab Automation"
echo "=========================="

# ====================================
# CONFIGURATION SECTION
# ====================================
# Edit these values with your lab configuration:

export FMC_HOST="https://your-tenant.us.cdo.cisco.com"      # Replace with your cdFMC URL
export SCC_URL="https://your-scc.us.cdo.cisco.com"         # Replace with your SCC URL
export FMC_API_TOKEN="YOUR_API_TOKEN_HERE"                  # Replace with your API token
export TARGET_DEVICE="NGFW1"                                # Fixed device name for lab

# ====================================
# END CONFIGURATION SECTION
# ====================================

# Validate configuration
if [ "$FMC_HOST" = "https://your-tenant.us.cdo.cisco.com" ] || [ "$SCC_URL" = "https://your-scc.us.cdo.cisco.com" ] || [ "$FMC_API_TOKEN" = "YOUR_API_TOKEN_HERE" ]; then
    echo "❌ ERROR: Please update the configuration values in run.sh!"
    echo "   Edit the values in the CONFIGURATION SECTION:"
    echo "   - FMC_HOST: Your cdFMC URL"
    echo "   - SCC_URL: Your SCC URL" 
    echo "   - FMC_API_TOKEN: Your API token"
    exit 1
fi

echo "✓ Configuration loaded from run.sh:"
echo "  FMC Host: $FMC_HOST"
echo "  SCC URL: $SCC_URL"
echo "  Device: $TARGET_DEVICE"
echo "  Token: ${FMC_API_TOKEN:0:10}...${FMC_API_TOKEN: -4}"
echo ""

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment"
        exit 1
    fi
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/bin/activate

# Check if dependencies are installed in venv
if ! python -c "import requests" 2>/dev/null; then
    echo "📚 Installing dependencies in virtual environment..."
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies"
        exit 1
    fi
    echo "✓ Dependencies installed"
else
    echo "✓ Dependencies already installed"
fi

# Run the automation
echo "🚀 Running Caldera Lab Automation..."
python caldera_automation.py

# Capture exit code
EXIT_CODE=$?

# Deactivate virtual environment
deactivate

# Exit with the same code as the Python script
exit $EXIT_CODE

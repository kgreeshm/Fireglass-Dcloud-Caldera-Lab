#!/bin/bash
# Enhanced runner for Caldera Lab Automation with automatic venv management

echo "🚀 Caldera Lab Automation"
echo "=========================="

# ====================================
# CONFIGURATION SECTION
# ====================================
# Configuration is loaded from inputs.sh
# Edit inputs.sh file to set your lab configuration

# Check if inputs.sh exists
if [ ! -f "inputs.sh" ]; then
    echo "❌ Error: inputs.sh file not found"
    echo "   Please create inputs.sh with your lab configuration"
    echo "   See README.md for instructions"
    exit 1
fi

# Load configuration from inputs.sh
echo "🔧 Loading configuration from inputs.sh..."
source inputs.sh

# ====================================
# END CONFIGURATION SECTION
# ====================================

# Validate configuration
if [ "$FMC_HOST" = "https://your-cdo-instance.app.region.cdo.cisco.com" ] || [ "$FMC_API_TOKEN" = "your-api-token-here" ]; then
    echo "❌ ERROR: Please update the configuration values in inputs.sh!"
    echo "   Edit the values in inputs.sh file:"
    echo "   - FMC_HOST: Your cdFMC URL"
    echo "   - FMC_API_TOKEN: Your API token"
    exit 1
fi

echo "✓ Configuration loaded from inputs.sh:"
echo "  FMC Host: $FMC_HOST"
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
echo "🚀 Running Caldera Lab Automation (Modular Version)..."
echo ""
echo "Available automation options:"
echo "  1. Full automation (recommended): python caldera_lab.py"
echo "  2. Individual modules for troubleshooting:"
echo "     - File Policy only: python file_policy.py"
echo "     - Intrusion Policy only: python intrusion_policy.py"
echo "     - Access Policy only: python access_policy.py"
echo ""

# Export environment variables for Python modules
export FMC_HOST
export FMC_API_TOKEN
export TARGET_DEVICE

# Run the main orchestrator
python caldera_lab.py

# Capture exit code
EXIT_CODE=$?

# Deactivate virtual environment
deactivate

# Exit with the same code as the Python script
exit $EXIT_CODE

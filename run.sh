#!/bin/bash
# Enhanced runner for Caldera Lab Automation with automatic venv management

echo "🚀 Caldera Lab Automation"
echo "=========================="

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

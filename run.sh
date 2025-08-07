#!/bin/bash
# Simple runner for Caldera Lab Automation

echo "🚀 Caldera Lab Automation"
echo "=========================="

# Install dependencies if needed
if ! python -c "import requests" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Run the automation
python caldera_automation.py

#!/bin/bash

# Deployment script for AWS Vulnerability Remediation AI

echo "🚀 Deploying AWS Vulnerability Remediation AI..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Please copy .env.example to .env and configure it."
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Run tests
echo "🧪 Running tests..."
python -m pytest tests/ -v

# Start application
echo "🎯 Starting Streamlit application..."
streamlit run app.py
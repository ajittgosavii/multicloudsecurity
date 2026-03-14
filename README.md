# AWS Vulnerability Remediation AI

An AI-powered application for automatically detecting and remediating security vulnerabilities in AWS EC2, EKS, and Lambda services.

## Features

- 🔍 Comprehensive AWS resource scanning
- 🤖 AI-powered vulnerability analysis using AWS Bedrock
- ⚡ Automated remediation with one-click fixes
- 📊 Interactive dashboard with filtering and visualization
- 🛡️ Enterprise-grade security within AWS ecosystem

## Quick Start

1. Clone the repository
2. Copy `.env.example` to `.env` and configure AWS credentials
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `streamlit run app.py`

## Prerequisites

- AWS Account with appropriate permissions
- AWS Bedrock model access (Claude 3, Titan, or Jurassic-2)
- Python 3.8+
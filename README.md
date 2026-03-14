# Multi-Cloud Security Scanner

Automated vulnerability scanner for AWS infrastructure with AI-powered analysis and one-click remediation.

## What it does

- Scans **EC2, EKS, ECS, and Lambda** resources across multiple AWS regions simultaneously
- Detects security misconfigurations (open ports, IMDSv1, public endpoints, missing encryption, etc.)
- Integrates with **AWS Inspector** and **Security Hub** for additional findings
- Uses **AWS Bedrock** (Claude / Titan) to generate detailed remediation plans
- Provides automated remediation for common issues (enforce IMDSv2, enable logging, etc.)

## Architecture

```
app.py                  ← Streamlit dashboard entry point
src/
  cloud/
    connector.py        ← AWS session & client management
    scanner.py          ← Multi-region resource scanner
  analysis/
    ai_engine.py        ← Bedrock-powered vulnerability analysis
  remediation/
    executor.py         ← Automated remediation actions
  core/
    settings.py         ← Severity levels, resource types
.streamlit/
  config.toml           ← Theme & server config
```

## Setup

### Local

```bash
pip install -r requirements.txt
streamlit run app.py
```

Set these environment variables (or create a `.env` file):

```
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
```

### Streamlit Cloud

Add secrets in **Settings > Secrets** using TOML format:

```toml
AWS_ACCESS_KEY_ID = "..."
AWS_SECRET_ACCESS_KEY = "..."
AWS_REGION = "us-east-1"
BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"
```

## Requirements

- Python 3.12+
- AWS account with EC2, EKS, ECS, Lambda, Bedrock access
- IAM credentials with read permissions (+ write for remediation)

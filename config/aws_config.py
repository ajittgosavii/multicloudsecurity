import boto3
import os
from dotenv import load_dotenv

load_dotenv()

def _get_secret(key, default=None):
    """Read from Streamlit secrets first, then fall back to env vars."""
    try:
        import streamlit as st
        return st.secrets.get(key, os.getenv(key, default))
    except Exception:
        return os.getenv(key, default)

# All AWS regions that support EC2/EKS/ECS/Lambda
ALL_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2',
    'ca-central-1',
    'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
    'sa-east-1',
]

class AWSConfig:
    def __init__(self):
        self.region = _get_secret('AWS_REGION', 'us-east-1')
        self.access_key = _get_secret('AWS_ACCESS_KEY_ID')
        self.secret_key = _get_secret('AWS_SECRET_ACCESS_KEY')
        self.bedrock_model = _get_secret('BEDROCK_MODEL_ID')

    def get_session(self, region=None):
        return boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=region or self.region
        )

    def get_clients(self, region=None):
        session = self.get_session(region)
        return {
            'ec2': session.client('ec2'),
            'eks': session.client('eks'),
            'ecs': session.client('ecs'),
            'lambda': session.client('lambda'),
            'securityhub': session.client('securityhub'),
            'inspector2': session.client('inspector2'),
            'ssm': session.client('ssm'),
            'bedrock-runtime': session.client('bedrock-runtime', region_name=region or self.region),
            'iam': session.client('iam')
        }

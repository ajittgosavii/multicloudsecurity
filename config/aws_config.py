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

class AWSConfig:
    def __init__(self):
        self.region = _get_secret('AWS_REGION', 'us-east-1')
        self.access_key = _get_secret('AWS_ACCESS_KEY_ID')
        self.secret_key = _get_secret('AWS_SECRET_ACCESS_KEY')
        self.bedrock_model = _get_secret('BEDROCK_MODEL_ID')
        
    def get_session(self):
        return boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region
        )
    
    def get_clients(self):
        session = self.get_session()
        return {
            'ec2': session.client('ec2'),
            'eks': session.client('eks'),
            'lambda': session.client('lambda'),
            'securityhub': session.client('securityhub'),
            'inspector2': session.client('inspector2'),
            'ssm': session.client('ssm'),
            'bedrock-runtime': session.client('bedrock-runtime', region_name=self.region),
            'iam': session.client('iam')
        }
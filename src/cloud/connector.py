import boto3
import os
from dotenv import load_dotenv

load_dotenv()

ALL_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2',
    'ca-central-1',
    'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
    'sa-east-1',
]


def _get_secret(key, default=None):
    try:
        import streamlit as st
        return st.secrets.get(key, os.getenv(key, default))
    except Exception:
        return os.getenv(key, default)


class AWSConnector:
    def __init__(self):
        self.default_region = _get_secret('AWS_REGION', 'us-east-1')
        self._access_key = _get_secret('AWS_ACCESS_KEY_ID')
        self._secret_key = _get_secret('AWS_SECRET_ACCESS_KEY')
        self.bedrock_model = _get_secret('BEDROCK_MODEL_ID')

    def session(self, region=None):
        return boto3.Session(
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            region_name=region or self.default_region,
        )

    def clients(self, region=None):
        s = self.session(region)
        r = region or self.default_region
        return {
            'ec2': s.client('ec2'),
            'eks': s.client('eks'),
            'ecs': s.client('ecs'),
            'lambda': s.client('lambda'),
            'securityhub': s.client('securityhub'),
            'inspector2': s.client('inspector2'),
            'ssm': s.client('ssm'),
            'iam': s.client('iam'),
            'bedrock-runtime': s.client('bedrock-runtime', region_name=r),
        }

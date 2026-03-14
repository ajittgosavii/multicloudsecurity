import boto3
import os
from dotenv import load_dotenv

load_dotenv()

class AWSConfig:
    def __init__(self):
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.access_key = os.getenv('AWS_ACCESS_KEY_ID')
        self.secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.bedrock_model = os.getenv('BEDROCK_MODEL_ID')
        
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
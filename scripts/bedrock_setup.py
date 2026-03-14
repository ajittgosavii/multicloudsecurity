#!/usr/bin/env python3
"""
Script to setup and verify AWS Bedrock access
"""

import boto3
import json
from botocore.exceptions import ClientError

def check_bedrock_access():
    """Check if Bedrock is accessible and list available models"""
    try:
        bedrock = boto3.client('bedrock', region_name='us-east-1')
        
        # List foundation models
        response = bedrock.list_foundation_models()
        
        print("✅ AWS Bedrock access verified!")
        print("\nAvailable models:")
        
        for model in response['modelSummaries']:
            print(f"  - {model['modelId']} ({model['modelName']})")
            
        return True
        
    except ClientError as e:
        print(f"❌ Bedrock access error: {e}")
        return False

if __name__ == "__main__":
    check_bedrock_access()
import re

def validate_aws_resource_id(resource_id: str, resource_type: str) -> bool:
    """Validate AWS resource ID format"""
    patterns = {
        'EC2': r'^i-[0-9a-f]{8,17}$',
        'EKS': r'^[a-zA-Z0-9][a-zA-Z0-9\-]{1,99}$',
        'LAMBDA': r'^[a-zA-Z0-9-_]{1,64}$'
    }
    
    pattern = patterns.get(resource_type)
    if pattern and re.match(pattern, resource_id):
        return True
    return False

def validate_severity(severity: str) -> bool:
    """Validate severity level"""
    valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    return severity.upper() in valid_severities
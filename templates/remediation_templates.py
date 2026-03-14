# Pre-defined remediation templates for common vulnerabilities

REMEDIATION_TEMPLATES = {
    'EC2-PUBLIC-IP': {
        'name': 'Move EC2 to Private Subnet',
        'description': 'Move EC2 instance from public to private subnet',
        'steps': [
            'Identify the current subnet',
            'Create or identify a private subnet',
            'Stop the EC2 instance',
            'Change the subnet association',
            'Start the EC2 instance'
        ]
    },
    'SG-OPEN-SSH': {
        'name': 'Restrict SSH Access',
        'description': 'Restrict SSH access to specific IP ranges',
        'steps': [
            'Identify the security group rule',
            'Determine authorized IP ranges',
            'Update security group ingress rules',
            'Test connectivity from authorized IPs'
        ]
    }
    # ... more templates
}
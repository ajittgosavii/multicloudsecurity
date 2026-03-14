# Severity levels
SEVERITY_LEVELS = {
    'CRITICAL': {'color': '#FF0000', 'priority': 1},
    'HIGH': {'color': '#FF4B4B', 'priority': 2},
    'MEDIUM': {'color': '#FFA500', 'priority': 3},
    'LOW': {'color': '#008000', 'priority': 4},
    'INFO': {'color': '#0066CC', 'priority': 5}
}

# Resource types
RESOURCE_TYPES = {
    'EC2': {'icon': '🖥️', 'service': 'ec2'},
    'EKS': {'icon': '☸️', 'service': 'eks'},
    'ECS': {'icon': '📦', 'service': 'ecs'},
    'LAMBDA': {'icon': 'λ', 'service': 'lambda'}
}

# AWS Service limits
SERVICE_LIMITS = {
    'MAX_EC2_SCAN': 100,
    'MAX_EKS_SCAN': 50,
    'MAX_LAMBDA_SCAN': 200
}

# Remediation status
REMEDIATION_STATUS = {
    'PENDING': 'pending',
    'IN_PROGRESS': 'in_progress',
    'COMPLETED': 'completed',
    'FAILED': 'failed',
    'SKIPPED': 'skipped'
}
SEVERITY_LEVELS = {
    'CRITICAL': {'color': '#FF0000', 'priority': 1},
    'HIGH': {'color': '#dc3545', 'priority': 2},
    'MEDIUM': {'color': '#fd7e14', 'priority': 3},
    'LOW': {'color': '#28a745', 'priority': 4},
    'INFO': {'color': '#0d6efd', 'priority': 5},
}

RESOURCE_TYPES = {
    'EC2': {'label': 'EC2 Instance', 'icon': '🖥️'},
    'EKS': {'label': 'EKS Cluster', 'icon': '☸️'},
    'ECS': {'label': 'ECS Cluster', 'icon': '📦'},
    'Lambda': {'label': 'Lambda Function', 'icon': 'λ'},
}

REMEDIATION_STATUS = {
    'PENDING': 'pending',
    'IN_PROGRESS': 'in_progress',
    'COMPLETED': 'completed',
    'FAILED': 'failed',
    'SKIPPED': 'skipped',
}

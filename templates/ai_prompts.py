# AI prompt templates for different vulnerability types

PROMPT_TEMPLATES = {
    'EC2': {
        'system_prompt': "You are an AWS security expert specializing in EC2 instance security...",
        'user_template': "Analyze this EC2 vulnerability: {vulnerability_details}..."
    },
    'EKS': {
        'system_prompt': "You are a Kubernetes security expert specializing in EKS security...",
        'user_template': "Analyze this EKS cluster vulnerability: {vulnerability_details}..."
    },
    'LAMBDA': {
        'system_prompt': "You are an AWS Lambda security expert...",
        'user_template': "Analyze this Lambda function vulnerability: {vulnerability_details}..."
    }
}
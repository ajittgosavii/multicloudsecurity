import boto3
import json
from typing import Dict, List, Any
from config.constants import REMEDIATION_STATUS

class RemediationEngine:
    def __init__(self, aws_clients):
        self.clients = aws_clients
        self.remediation_history = []
    
    def remediate_vulnerability(self, resource_type: str, resource_id: str, 
                              vulnerability: Dict, remediation_data: Dict) -> Dict:
        """Execute remediation for a specific vulnerability"""
        
        remediation_id = f"{resource_id}_{vulnerability['id']}"
        
        try:
            if resource_type == 'EC2':
                result = self._remediate_ec2(resource_id, vulnerability, remediation_data)
            elif resource_type == 'EKS':
                result = self._remediate_eks(resource_id, vulnerability, remediation_data)
            elif resource_type == 'Lambda':
                result = self._remediate_lambda(resource_id, vulnerability, remediation_data)
            else:
                result = {'status': 'error', 'message': f'Unsupported resource type: {resource_type}'}
            
            # Log remediation attempt
            self._log_remediation(
                remediation_id, resource_type, resource_id, 
                vulnerability, result
            )
            
            return result
                
        except Exception as e:
            error_result = {'status': 'error', 'message': f'Remediation failed: {str(e)}'}
            self._log_remediation(
                remediation_id, resource_type, resource_id, 
                vulnerability, error_result
            )
            return error_result
    
    def _remediate_ec2(self, instance_id: str, vulnerability: Dict, remediation_data: Dict) -> Dict:
        """Remediate EC2 vulnerabilities"""
        vuln_id = vulnerability.get('id', '')
        
        if 'SG-OPEN' in vuln_id:
            return self._remediate_open_security_group(instance_id, vulnerability)
        elif 'EC2-IMDS-V1' in vuln_id:
            return self._remediate_imdsv1(instance_id)
        elif 'EC2-PUBLIC-IP' in vuln_id:
            return self._remediate_public_ip(instance_id)
        else:
            return {'status': 'skipped', 'message': 'Automatic remediation not available for this vulnerability'}
    
    def _remediate_eks(self, cluster_name: str, vulnerability: Dict, remediation_data: Dict) -> Dict:
        """Remediate EKS vulnerabilities"""
        vuln_id = vulnerability.get('id', '')
        
        if 'EKS-LOGGING-DISABLED' in vuln_id:
            return self._remediate_eks_logging(cluster_name)
        else:
            return {'status': 'info', 'message': 'EKS remediation requires manual review in demo mode'}
    
    def _remediate_lambda(self, function_name: str, vulnerability: Dict, remediation_data: Dict) -> Dict:
        """Remediate Lambda vulnerabilities"""
        return {'status': 'info', 'message': 'Lambda remediation requires manual review in demo mode'}
    
    # ... (implementation of specific remediation methods)
    
    def _log_remediation(self, remediation_id: str, resource_type: str, 
                        resource_id: str, vulnerability: Dict, result: Dict):
        """Log remediation attempts for audit purposes"""
        log_entry = {
            'remediation_id': remediation_id,
            'timestamp': boto3.Session().client('sts').get_caller_identity()['Arn'],
            'resource_type': resource_type,
            'resource_id': resource_id,
            'vulnerability': vulnerability,
            'result': result,
            'status': result.get('status', 'unknown')
        }
        self.remediation_history.append(log_entry)
    
    def get_remediation_history(self):
        """Get remediation history"""
        return self.remediation_history
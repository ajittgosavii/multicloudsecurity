from typing import Dict
from datetime import datetime


class RemediationExecutor:
    """Executes automated remediation actions against AWS resources."""

    def __init__(self, clients):
        self.clients = clients
        self.history = []

    def remediate(self, resource_type: str, resource_id: str,
                  vulnerability: Dict, analysis: Dict) -> Dict:
        handlers = {
            'EC2': self._handle_ec2,
            'EKS': self._handle_eks,
            'ECS': self._handle_ecs,
            'Lambda': self._handle_lambda,
        }
        handler = handlers.get(resource_type)
        if not handler:
            return {'status': 'error', 'message': f'Unsupported resource type: {resource_type}'}

        try:
            result = handler(resource_id, vulnerability, analysis)
        except Exception as exc:
            result = {'status': 'error', 'message': f'Remediation failed: {exc}'}

        self.history.append({
            'timestamp': datetime.utcnow().isoformat(),
            'resource_type': resource_type,
            'resource_id': resource_id,
            'vulnerability_id': vulnerability.get('id'),
            'result': result,
        })
        return result

    # ------------------------------------------------------------------
    # Per-service handlers
    # ------------------------------------------------------------------

    def _handle_ec2(self, instance_id, vuln, analysis):
        vid = vuln.get('id', '')
        if 'EC2-IMDS-V1' in vid:
            self.clients['ec2'].modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens='required',
                HttpEndpoint='enabled',
            )
            return {'status': 'success', 'message': f'Enforced IMDSv2 on {instance_id}'}
        if 'SG-OPEN' in vid:
            return {'status': 'info', 'message': 'Security group remediation requires manual review to avoid lockout'}
        if 'EC2-PUBLIC-IP' in vid:
            return {'status': 'info', 'message': 'Public IP removal requires instance migration planning'}
        return {'status': 'skipped', 'message': 'No automatic remediation available'}

    def _handle_eks(self, cluster_name, vuln, analysis):
        vid = vuln.get('id', '')
        if 'EKS-LOGGING-DISABLED' in vid:
            self.clients['eks'].update_cluster_config(
                name=cluster_name,
                logging={'clusterLogging': [
                    {'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
                     'enabled': True}
                ]}
            )
            return {'status': 'success', 'message': f'Enabled control plane logging on {cluster_name}'}
        return {'status': 'info', 'message': 'EKS remediation requires manual review'}

    def _handle_ecs(self, cluster_name, vuln, analysis):
        vid = vuln.get('id', '')
        if 'ECS-NO-CONTAINER-INSIGHTS' in vid:
            self.clients['ecs'].update_cluster_settings(
                cluster=cluster_name,
                settings=[{'name': 'containerInsights', 'value': 'enabled'}],
            )
            return {'status': 'success', 'message': f'Enabled Container Insights on {cluster_name}'}
        return {'status': 'info', 'message': 'ECS remediation requires manual review'}

    def _handle_lambda(self, function_name, vuln, analysis):
        return {'status': 'info', 'message': 'Lambda remediation requires manual review'}

from typing import Dict, List
from .connector import AWSConnector


class MultiRegionScanner:
    """Scans EC2, EKS, ECS, and Lambda across one or more AWS regions."""

    def __init__(self, connector: AWSConnector):
        self.connector = connector

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(self, regions: List[str], on_progress=None):
        """Scan all services in the given regions.

        Returns (resources, errors) where resources is a flat list and
        errors is a list of region-level error strings.
        """
        resources: List[Dict] = []
        errors: List[str] = []

        for idx, region in enumerate(regions):
            if on_progress:
                on_progress(region, idx, len(regions))

            try:
                clients = self.connector.clients(region)
                resources.extend(self._scan_ec2(clients, region))
                resources.extend(self._scan_eks(clients, region))
                resources.extend(self._scan_ecs(clients, region))
                resources.extend(self._scan_lambda(clients, region))
            except Exception as exc:
                errors.append(f"{region}: {exc}")

        return resources, errors

    # ------------------------------------------------------------------
    # EC2
    # ------------------------------------------------------------------

    def _scan_ec2(self, clients, region) -> List[Dict]:
        try:
            instances = []
            resp = clients['ec2'].describe_instances()
            for reservation in resp['Reservations']:
                for inst in reservation['Instances']:
                    vulns = self._ec2_checks(inst, clients)
                    vulns.extend(self._inspector_findings(clients, inst['InstanceId']))
                    vulns.extend(self._security_hub_findings(clients, inst['InstanceId']))

                    name = next(
                        (t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'),
                        'N/A',
                    )
                    instances.append({
                        'resource_id': inst['InstanceId'],
                        'resource_name': name,
                        'resource_type': 'EC2',
                        'region': region,
                        'state': inst['State']['Name'],
                        'instance_type': inst.get('InstanceType', 'N/A'),
                        'launch_time': inst['LaunchTime'].isoformat(),
                        'vpc_id': inst.get('VpcId', 'N/A'),
                        'subnet_id': inst.get('SubnetId', 'N/A'),
                        'public_ip': inst.get('PublicIpAddress', 'N/A'),
                        'security_groups': [sg['GroupId'] for sg in inst.get('SecurityGroups', [])],
                        'vulnerabilities': vulns,
                    })
            return instances
        except Exception as exc:
            print(f"EC2 scan error [{region}]: {exc}")
            return []

    def _ec2_checks(self, inst, clients) -> List[Dict]:
        vulns = []
        if inst.get('PublicIpAddress'):
            vulns.append(self._vuln('EC2-PUBLIC-IP', 'EC2 Instance has Public IP', 'HIGH',
                                    'Instance is directly accessible from the internet',
                                    'Move to private subnet or use NAT gateway'))
        for sg in inst.get('SecurityGroups', []):
            vulns.extend(self._sg_checks(clients, sg['GroupId']))
        meta = inst.get('MetadataOptions', {})
        if meta.get('HttpTokens') != 'required':
            vulns.append(self._vuln('EC2-IMDS-V1', 'IMDSv1 Enabled', 'MEDIUM',
                                    'Instance Metadata Service v1 is enabled, less secure than v2',
                                    'Enforce IMDSv2 only'))
        return vulns

    def _sg_checks(self, clients, sg_id) -> List[Dict]:
        vulns = []
        try:
            resp = clients['ec2'].describe_security_group_rules(
                Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
            )
            for rule in resp['SecurityGroupRules']:
                if rule.get('IsEgress'):
                    continue
                cidr = rule.get('CidrIpv4', '')
                port = rule.get('FromPort')
                if cidr != '0.0.0.0/0':
                    continue
                if port == 22:
                    vulns.append(self._vuln('SG-OPEN-SSH', 'SSH Open To Internet', 'HIGH',
                                            'Security group allows SSH from 0.0.0.0/0',
                                            'Restrict SSH access to specific IP ranges'))
                elif port == 3389:
                    vulns.append(self._vuln('SG-OPEN-RDP', 'RDP Open To Internet', 'HIGH',
                                            'Security group allows RDP from 0.0.0.0/0',
                                            'Restrict RDP access to specific IP ranges'))
                else:
                    vulns.append(self._vuln(
                        f'SG-OPEN-{port or "ANY"}',
                        f'Port {port or "Any"} Open To Internet', 'MEDIUM',
                        f'Security group allows {rule["IpProtocol"]} port {port or "Any"} from 0.0.0.0/0',
                        'Restrict source IP range to specific networks'))
        except Exception as exc:
            print(f"SG check error [{sg_id}]: {exc}")
        return vulns

    # ------------------------------------------------------------------
    # EKS
    # ------------------------------------------------------------------

    def _scan_eks(self, clients, region) -> List[Dict]:
        try:
            clusters = []
            for name in clients['eks'].list_clusters()['clusters']:
                data = clients['eks'].describe_cluster(name=name)['cluster']
                vulns = self._eks_checks(data)
                clusters.append({
                    'resource_id': data['name'],
                    'resource_name': data['name'],
                    'resource_type': 'EKS',
                    'region': region,
                    'status': data['status'],
                    'version': data['version'],
                    'arn': data['arn'],
                    'endpoint': data.get('endpoint', 'N/A'),
                    'resources_vpc_config': data.get('resourcesVpcConfig', {}),
                    'vulnerabilities': vulns,
                })
            return clusters
        except Exception as exc:
            print(f"EKS scan error [{region}]: {exc}")
            return []

    def _eks_checks(self, data) -> List[Dict]:
        vulns = []
        logging_cfg = data.get('logging', {}).get('clusterLogging', [{}])[0]
        if not logging_cfg.get('enabled'):
            vulns.append(self._vuln('EKS-LOGGING-DISABLED', 'EKS Control Plane Logging Disabled', 'MEDIUM',
                                    'Control plane logging is not enabled',
                                    'Enable control plane logging for all log types'))
        vpc = data.get('resourcesVpcConfig', {})
        if vpc.get('endpointPublicAccess') and not vpc.get('endpointPrivateAccess'):
            vulns.append(self._vuln('EKS-PUBLIC-ENDPOINT', 'EKS Public Endpoint Without Private Access', 'HIGH',
                                    'Cluster endpoint is public without private access enabled',
                                    'Disable public endpoint or enable private access'))
        if not data.get('encryptionConfig'):
            vulns.append(self._vuln('EKS-NO-ENCRYPTION', 'EKS Secrets Not Encrypted with KMS', 'MEDIUM',
                                    'Kubernetes secrets are not encrypted with a KMS key',
                                    'Enable KMS encryption for Kubernetes secrets'))
        return vulns

    # ------------------------------------------------------------------
    # ECS
    # ------------------------------------------------------------------

    def _scan_ecs(self, clients, region) -> List[Dict]:
        try:
            arns = clients['ecs'].list_clusters().get('clusterArns', [])
            if not arns:
                return []
            desc = clients['ecs'].describe_clusters(
                clusters=arns,
                include=['SETTINGS', 'CONFIGURATIONS', 'STATISTICS'],
            )
            results = []
            for c in desc.get('clusters', []):
                vulns = self._ecs_checks(c)
                services = self._ecs_services(clients, c['clusterArn'])
                results.append({
                    'resource_id': c['clusterName'],
                    'resource_name': c['clusterName'],
                    'resource_type': 'ECS',
                    'region': region,
                    'status': c.get('status', 'N/A'),
                    'running_tasks': c.get('runningTasksCount', 0),
                    'pending_tasks': c.get('pendingTasksCount', 0),
                    'active_services': c.get('activeServicesCount', 0),
                    'capacity_providers': c.get('capacityProviders', []),
                    'arn': c['clusterArn'],
                    'services': services,
                    'vulnerabilities': vulns,
                })
            return results
        except Exception as exc:
            print(f"ECS scan error [{region}]: {exc}")
            return []

    def _ecs_checks(self, cluster) -> List[Dict]:
        vulns = []
        insights_on = any(
            s.get('name') == 'containerInsights' and s.get('value') == 'enabled'
            for s in cluster.get('settings', [])
        )
        if not insights_on:
            vulns.append(self._vuln('ECS-NO-CONTAINER-INSIGHTS', 'Container Insights Disabled', 'MEDIUM',
                                    'Container Insights is not enabled for monitoring',
                                    'Enable Container Insights for the cluster'))
        if not cluster.get('capacityProviders'):
            vulns.append(self._vuln('ECS-NO-CAPACITY-PROVIDER', 'No Capacity Provider Strategy', 'LOW',
                                    'Cluster has no capacity provider strategy configured',
                                    'Configure a capacity provider strategy'))
        exec_cfg = cluster.get('configuration', {}).get('executeCommandConfiguration', {})
        if not exec_cfg.get('logging'):
            vulns.append(self._vuln('ECS-EXEC-NO-LOGGING', 'ECS Exec Logging Not Configured', 'MEDIUM',
                                    'ECS Exec logging is not configured for audit trail',
                                    'Enable ECS Exec logging to CloudWatch or S3'))
        return vulns

    def _ecs_services(self, clients, cluster_arn) -> List[Dict]:
        try:
            svc_arns = clients['ecs'].list_services(cluster=cluster_arn, maxResults=100).get('serviceArns', [])
            if not svc_arns:
                return []
            desc = clients['ecs'].describe_services(cluster=cluster_arn, services=svc_arns)
            return [{
                'name': s['serviceName'],
                'status': s.get('status', 'N/A'),
                'desired_count': s.get('desiredCount', 0),
                'running_count': s.get('runningCount', 0),
                'launch_type': s.get('launchType', 'N/A'),
                'task_definition': s.get('taskDefinition', 'N/A'),
            } for s in desc.get('services', [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Lambda
    # ------------------------------------------------------------------

    def _scan_lambda(self, clients, region) -> List[Dict]:
        try:
            funcs = []
            paginator = clients['lambda'].get_paginator('list_functions')
            for page in paginator.paginate():
                for fn in page['Functions']:
                    vulns = self._lambda_checks(fn)
                    funcs.append({
                        'resource_id': fn['FunctionName'],
                        'resource_name': fn['FunctionName'],
                        'resource_type': 'Lambda',
                        'region': region,
                        'runtime': fn.get('Runtime', 'N/A'),
                        'last_modified': fn['LastModified'],
                        'memory_size': fn.get('MemorySize', 'N/A'),
                        'timeout': fn.get('Timeout', 'N/A'),
                        'arn': fn['FunctionArn'],
                        'vulnerabilities': vulns,
                    })
            return funcs
        except Exception as exc:
            print(f"Lambda scan error [{region}]: {exc}")
            return []

    def _lambda_checks(self, fn) -> List[Dict]:
        vulns = []
        if fn.get('Role'):
            vulns.append(self._vuln('LAMBDA-POLICY-REVIEW', 'Lambda IAM Policy Needs Review', 'MEDIUM',
                                    'Execution role may have excessive permissions',
                                    'Review and restrict IAM permissions (least privilege)'))
        if fn.get('Environment', {}).get('Variables'):
            vulns.append(self._vuln('LAMBDA-ENV-VARS', 'Lambda Uses Environment Variables', 'LOW',
                                    'Environment variables may contain secrets',
                                    'Use Secrets Manager instead of env vars'))
        if not fn.get('VpcConfig'):
            vulns.append(self._vuln('LAMBDA-NO-VPC', 'Lambda Not in VPC', 'LOW',
                                    'Function is not deployed in a VPC',
                                    'Deploy in VPC for enhanced network security'))
        return vulns

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _inspector_findings(self, clients, resource_id) -> List[Dict]:
        try:
            resp = clients['inspector2'].list_findings(
                filterCriteria={
                    'resourceId': [{'comparison': 'EQUALS', 'value': resource_id}],
                    'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}],
                    'severity': [
                        {'comparison': 'EQUALS', 'value': 'HIGH'},
                        {'comparison': 'EQUALS', 'value': 'MEDIUM'},
                    ],
                },
                maxResults=50,
            )
            return [self._vuln(
                f"INSPECTOR-{f.get('findingArn', '').split('/')[-1]}",
                f.get('title', 'Inspector Finding'),
                f.get('severity', 'MEDIUM').upper(),
                f.get('description', 'AWS Inspector finding'),
                f.get('remediation', {}).get('recommendation', {}).get('text', 'Review in Inspector'),
                source='inspector',
            ) for f in resp.get('findings', [])]
        except Exception:
            return []

    def _security_hub_findings(self, clients, resource_id) -> List[Dict]:
        try:
            resp = clients['securityhub'].get_findings(
                Filters={
                    'ResourceId': [{'Value': resource_id, 'Comparison': 'EQUALS'}],
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                    'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}],
                },
                MaxResults=50,
            )
            return [self._vuln(
                f"SECHUB-{f.get('Id', '').split('/')[-1]}",
                f.get('Title', 'Security Hub Finding'),
                f.get('Severity', {}).get('Label', 'MEDIUM').upper(),
                f.get('Description', 'Security Hub finding'),
                f.get('Remediation', {}).get('Recommendation', {}).get('Text', 'Review in Security Hub'),
                source='securityhub',
            ) for f in resp.get('Findings', [])]
        except Exception:
            return []

    @staticmethod
    def _vuln(vid, title, severity, description, remediation, source='custom'):
        return {
            'id': vid,
            'title': title,
            'severity': severity,
            'description': description,
            'remediation': remediation,
            'source': source,
        }

import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any

class AWSScanner:
    def __init__(self, aws_clients, region='us-east-1'):
        self.clients = aws_clients
        self.region = region

    def scan_ec2_instances(self) -> List[Dict]:
        """Scan EC2 instances for vulnerabilities using multiple AWS services"""
        try:
            instances = []
            response = self.clients['ec2'].describe_instances()

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    vulnerabilities = self._check_ec2_vulnerabilities(instance)

                    inspector_findings = self._get_inspector_findings(instance['InstanceId'])
                    vulnerabilities.extend(inspector_findings)

                    security_hub_findings = self._get_security_hub_findings(instance['InstanceId'])
                    vulnerabilities.extend(security_hub_findings)

                    name = 'N/A'
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break

                    instance_data = {
                        'resource_id': instance['InstanceId'],
                        'resource_name': name,
                        'resource_type': 'EC2',
                        'region': self.region,
                        'state': instance['State']['Name'],
                        'instance_type': instance.get('InstanceType', 'N/A'),
                        'launch_time': instance['LaunchTime'].isoformat(),
                        'vpc_id': instance.get('VpcId', 'N/A'),
                        'subnet_id': instance.get('SubnetId', 'N/A'),
                        'public_ip': instance.get('PublicIpAddress', 'N/A'),
                        'vulnerabilities': vulnerabilities,
                        'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    }
                    instances.append(instance_data)

            return instances
        except Exception as e:
            print(f"EC2 scan error in {self.region}: {e}")
            return []

    def scan_eks_clusters(self) -> List[Dict]:
        """Scan EKS clusters for vulnerabilities"""
        try:
            clusters = []
            response = self.clients['eks'].list_clusters()

            for cluster_name in response['clusters']:
                cluster_info = self.clients['eks'].describe_cluster(name=cluster_name)
                cluster_data = cluster_info['cluster']

                vulnerabilities = self._check_eks_vulnerabilities(cluster_data)

                cluster = {
                    'resource_id': cluster_data['name'],
                    'resource_name': cluster_data['name'],
                    'resource_type': 'EKS',
                    'region': self.region,
                    'status': cluster_data['status'],
                    'version': cluster_data['version'],
                    'arn': cluster_data['arn'],
                    'endpoint': cluster_data.get('endpoint', 'N/A'),
                    'vulnerabilities': vulnerabilities,
                    'resources_vpc_config': cluster_data.get('resourcesVpcConfig', {})
                }
                clusters.append(cluster)

            return clusters
        except Exception as e:
            print(f"EKS scan error in {self.region}: {e}")
            return []

    def scan_ecs_clusters(self) -> List[Dict]:
        """Scan ECS clusters and services for vulnerabilities"""
        try:
            clusters = []
            list_response = self.clients['ecs'].list_clusters()
            cluster_arns = list_response.get('clusterArns', [])

            if not cluster_arns:
                return []

            describe_response = self.clients['ecs'].describe_clusters(
                clusters=cluster_arns,
                include=['SETTINGS', 'CONFIGURATIONS', 'STATISTICS']
            )

            for cluster_data in describe_response.get('clusters', []):
                vulnerabilities = self._check_ecs_vulnerabilities(cluster_data)

                # Get services in this cluster
                services_info = self._get_ecs_services(cluster_data['clusterArn'])

                cluster = {
                    'resource_id': cluster_data['clusterName'],
                    'resource_name': cluster_data['clusterName'],
                    'resource_type': 'ECS',
                    'region': self.region,
                    'status': cluster_data.get('status', 'N/A'),
                    'running_tasks': cluster_data.get('runningTasksCount', 0),
                    'pending_tasks': cluster_data.get('pendingTasksCount', 0),
                    'active_services': cluster_data.get('activeServicesCount', 0),
                    'capacity_providers': cluster_data.get('capacityProviders', []),
                    'arn': cluster_data['clusterArn'],
                    'services': services_info,
                    'vulnerabilities': vulnerabilities,
                }
                clusters.append(cluster)

            return clusters
        except Exception as e:
            print(f"ECS scan error in {self.region}: {e}")
            return []

    def _get_ecs_services(self, cluster_arn: str) -> List[Dict]:
        """Get ECS services for a cluster"""
        try:
            services = []
            list_resp = self.clients['ecs'].list_services(cluster=cluster_arn, maxResults=100)
            service_arns = list_resp.get('serviceArns', [])

            if not service_arns:
                return []

            desc_resp = self.clients['ecs'].describe_services(
                cluster=cluster_arn,
                services=service_arns
            )

            for svc in desc_resp.get('services', []):
                services.append({
                    'name': svc['serviceName'],
                    'status': svc.get('status', 'N/A'),
                    'desired_count': svc.get('desiredCount', 0),
                    'running_count': svc.get('runningCount', 0),
                    'launch_type': svc.get('launchType', 'N/A'),
                    'task_definition': svc.get('taskDefinition', 'N/A'),
                })

            return services
        except Exception as e:
            print(f"ECS services error: {e}")
            return []

    def _check_ecs_vulnerabilities(self, cluster_data: Dict) -> List[Dict]:
        """Check ECS cluster for vulnerabilities"""
        vulnerabilities = []

        # Check Container Insights
        settings = cluster_data.get('settings', [])
        container_insights_enabled = False
        for setting in settings:
            if setting.get('name') == 'containerInsights' and setting.get('value') == 'enabled':
                container_insights_enabled = True
                break

        if not container_insights_enabled:
            vulnerabilities.append({
                'id': 'ECS-NO-CONTAINER-INSIGHTS',
                'title': 'ECS Container Insights Disabled',
                'severity': 'MEDIUM',
                'description': 'Container Insights is not enabled for monitoring and observability',
                'remediation': 'Enable Container Insights for the cluster',
                'source': 'custom'
            })

        # Check if using default capacity provider (EC2 without Fargate)
        capacity_providers = cluster_data.get('capacityProviders', [])
        if not capacity_providers:
            vulnerabilities.append({
                'id': 'ECS-NO-CAPACITY-PROVIDER',
                'title': 'ECS No Capacity Provider Strategy',
                'severity': 'LOW',
                'description': 'Cluster has no capacity provider strategy configured',
                'remediation': 'Configure capacity provider strategy for better resource management',
                'source': 'custom'
            })

        # Check execute command configuration
        config = cluster_data.get('configuration', {})
        exec_config = config.get('executeCommandConfiguration', {})
        if not exec_config.get('logging'):
            vulnerabilities.append({
                'id': 'ECS-EXEC-NO-LOGGING',
                'title': 'ECS Execute Command Logging Not Configured',
                'severity': 'MEDIUM',
                'description': 'ECS Exec logging is not configured for audit trail',
                'remediation': 'Enable ECS Exec logging to CloudWatch or S3',
                'source': 'custom'
            })

        return vulnerabilities

    def scan_lambda_functions(self) -> List[Dict]:
        """Scan Lambda functions for vulnerabilities"""
        try:
            functions = []
            paginator = self.clients['lambda'].get_paginator('list_functions')

            for page in paginator.paginate():
                for function in page['Functions']:
                    vulnerabilities = self._check_lambda_vulnerabilities(function)

                    function_data = {
                        'resource_id': function['FunctionName'],
                        'resource_name': function['FunctionName'],
                        'resource_type': 'Lambda',
                        'region': self.region,
                        'runtime': function.get('Runtime', 'N/A'),
                        'last_modified': function['LastModified'],
                        'memory_size': function.get('MemorySize', 'N/A'),
                        'timeout': function.get('Timeout', 'N/A'),
                        'arn': function['FunctionArn'],
                        'vulnerabilities': vulnerabilities
                    }
                    functions.append(function_data)

            return functions
        except Exception as e:
            print(f"Lambda scan error in {self.region}: {e}")
            return []

    def _get_inspector_findings(self, resource_id: str) -> List[Dict]:
        """Get AWS Inspector findings for a resource"""
        try:
            findings = []
            response = self.clients['inspector2'].list_findings(
                filterCriteria={
                    'resourceId': [{'comparison': 'EQUALS', 'value': resource_id}],
                    'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}],
                    'severity': [{'comparison': 'EQUALS', 'value': 'HIGH'},
                                {'comparison': 'EQUALS', 'value': 'MEDIUM'}]
                },
                maxResults=50
            )

            for finding in response.get('findings', []):
                findings.append({
                    'id': f"INSPECTOR-{finding.get('findingArn', '').split('/')[-1]}",
                    'title': finding.get('title', 'Inspector Finding'),
                    'severity': finding.get('severity', 'MEDIUM').upper(),
                    'description': finding.get('description', 'AWS Inspector finding'),
                    'remediation': finding.get('remediation', {}).get('recommendation', {}).get('text', 'Review in AWS Inspector'),
                    'source': 'inspector'
                })

            return findings
        except Exception as e:
            print(f"Inspector findings error: {e}")
            return []

    def _get_security_hub_findings(self, resource_id: str) -> List[Dict]:
        """Get AWS Security Hub findings for a resource"""
        try:
            findings = []
            response = self.clients['securityhub'].get_findings(
                Filters={
                    'ResourceId': [{'Value': resource_id, 'Comparison': 'EQUALS'}],
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                    'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
                },
                MaxResults=50
            )

            for finding in response.get('Findings', []):
                severity = finding.get('Severity', {}).get('Label', 'MEDIUM').upper()
                findings.append({
                    'id': f"SECHUB-{finding.get('Id', '').split('/')[-1]}",
                    'title': finding.get('Title', 'Security Hub Finding'),
                    'severity': severity,
                    'description': finding.get('Description', 'AWS Security Hub finding'),
                    'remediation': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', 'Review in AWS Security Hub'),
                    'source': 'securityhub'
                })

            return findings
        except Exception as e:
            print(f"Security Hub findings error: {e}")
            return []

    def _check_ec2_vulnerabilities(self, instance: Dict) -> List[Dict]:
        """Check EC2 instance for common vulnerabilities"""
        vulnerabilities = []

        if instance.get('PublicIpAddress'):
            vulnerabilities.append({
                'id': 'EC2-PUBLIC-IP',
                'title': 'EC2 Instance has Public IP',
                'severity': 'HIGH',
                'description': 'Instance is directly accessible from internet with public IP',
                'remediation': 'Move to private subnet or use NAT gateway',
                'source': 'custom'
            })

        for sg in instance.get('SecurityGroups', []):
            vulnerabilities.extend(self._check_security_group_rules(sg['GroupId']))

        metadata_options = instance.get('MetadataOptions', {})
        if metadata_options.get('HttpTokens') != 'required':
            vulnerabilities.append({
                'id': 'EC2-IMDS-V1',
                'title': 'IMDSv1 Enabled',
                'severity': 'MEDIUM',
                'description': 'Instance Metadata Service v1 is enabled, which is less secure than v2',
                'remediation': 'Enforce IMDSv2 only',
                'source': 'custom'
            })

        if 'vpc-' in instance.get('VpcId', '') and 'default' in instance.get('VpcId', ''):
            vulnerabilities.append({
                'id': 'EC2-DEFAULT-VPC',
                'title': 'Instance in Default VPC',
                'severity': 'LOW',
                'description': 'Instance is running in default VPC which is not security best practice',
                'remediation': 'Migrate instance to custom VPC',
                'source': 'custom'
            })

        return vulnerabilities

    def _check_eks_vulnerabilities(self, cluster: Dict) -> List[Dict]:
        """Check EKS cluster for vulnerabilities"""
        vulnerabilities = []

        logging = cluster.get('logging', {}).get('clusterLogging', [{}])[0]
        if not logging.get('enabled', False):
            vulnerabilities.append({
                'id': 'EKS-LOGGING-DISABLED',
                'title': 'EKS Control Plane Logging Disabled',
                'severity': 'MEDIUM',
                'description': 'Control plane logging is not enabled for audit purposes',
                'remediation': 'Enable control plane logging for all log types',
                'source': 'custom'
            })

        vpc_config = cluster.get('resourcesVpcConfig', {})
        if vpc_config.get('endpointPublicAccess', False):
            if not vpc_config.get('endpointPrivateAccess', False):
                vulnerabilities.append({
                    'id': 'EKS-PUBLIC-ENDPOINT',
                    'title': 'EKS Public Endpoint Without Private Access',
                    'severity': 'HIGH',
                    'description': 'Cluster has public endpoint enabled without private access',
                    'remediation': 'Disable public endpoint or enable private access',
                    'source': 'custom'
                })

        if not cluster.get('encryptionConfig'):
            vulnerabilities.append({
                'id': 'EKS-NO-ENCRYPTION',
                'title': 'EKS Secrets Not Encrypted with KMS',
                'severity': 'MEDIUM',
                'description': 'Kubernetes secrets are not encrypted with KMS keys',
                'remediation': 'Enable KMS encryption for Kubernetes secrets',
                'source': 'custom'
            })

        return vulnerabilities

    def _check_lambda_vulnerabilities(self, function: Dict) -> List[Dict]:
        """Check Lambda function for vulnerabilities"""
        vulnerabilities = []

        if function.get('Role'):
            vulnerabilities.append({
                'id': 'LAMBDA-POLICY-REVIEW',
                'title': 'Lambda Function Policy Needs Review',
                'severity': 'MEDIUM',
                'description': 'Function execution role may have excessive permissions',
                'remediation': 'Review and restrict IAM permissions following least privilege',
                'source': 'custom'
            })

        if function.get('Environment', {}).get('Variables'):
            vulnerabilities.append({
                'id': 'LAMBDA-ENV-VARS',
                'title': 'Lambda Has Environment Variables',
                'severity': 'LOW',
                'description': 'Function uses environment variables that may contain secrets',
                'remediation': 'Use AWS Secrets Manager for sensitive data instead of environment variables',
                'source': 'custom'
            })

        if not function.get('VpcConfig'):
            vulnerabilities.append({
                'id': 'LAMBDA-NO-VPC',
                'title': 'Lambda Function Not in VPC',
                'severity': 'LOW',
                'description': 'Function is not deployed in VPC, may access internet directly',
                'remediation': 'Consider deploying in VPC for enhanced network security',
                'source': 'custom'
            })

        return vulnerabilities

    def _check_security_group_rules(self, sg_id: str) -> List[Dict]:
        """Check security group rules for vulnerabilities"""
        vulnerabilities = []
        try:
            response = self.clients['ec2'].describe_security_group_rules(
                Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
            )

            for rule in response['SecurityGroupRules']:
                if rule.get('IsEgress', False):
                    continue

                if rule.get('CidrIpv4') == '0.0.0.0/0' and rule.get('FromPort') == 22:
                    vulnerabilities.append({
                        'id': 'SG-OPEN-SSH',
                        'title': 'SSH Open To Internet',
                        'severity': 'HIGH',
                        'description': 'Security group allows SSH from anywhere (0.0.0.0/0)',
                        'remediation': 'Restrict SSH access to specific IP ranges',
                        'source': 'custom'
                    })
                elif rule.get('CidrIpv4') == '0.0.0.0/0' and rule.get('FromPort') == 3389:
                    vulnerabilities.append({
                        'id': 'SG-OPEN-RDP',
                        'title': 'RDP Open To Internet',
                        'severity': 'HIGH',
                        'description': 'Security group allows RDP from anywhere (0.0.0.0/0)',
                        'remediation': 'Restrict RDP access to specific IP ranges',
                        'source': 'custom'
                    })
                elif rule.get('CidrIpv4') == '0.0.0.0/0':
                    vulnerabilities.append({
                        'id': f'SG-OPEN-{rule.get("FromPort", "ANY")}',
                        'title': f'Port {rule.get("FromPort", "Any")} Open To Internet',
                        'severity': 'MEDIUM',
                        'description': f'Security group allows {rule["IpProtocol"]} port {rule.get("FromPort", "Any")} from anywhere',
                        'remediation': 'Restrict source IP range to specific networks',
                        'source': 'custom'
                    })

        except Exception as e:
            print(f"Error checking security group {sg_id}: {str(e)}")

        return vulnerabilities

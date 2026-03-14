import pandas as pd
import plotly.express as px
from datetime import datetime
from typing import Dict, List, Any

class ReportGenerator:
    def __init__(self):
        pass
    
    def generate_summary_report(self, scan_results: Dict) -> Dict:
        """Generate summary report from scan results"""
        resources = scan_results.get('resources', [])
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        summary = {
            'scan_timestamp': scan_results.get('scan_time', datetime.now().isoformat()),
            'total_resources': len(resources),
            'total_vulnerabilities': len(vulnerabilities),
            'resources_by_type': self._count_resources_by_type(resources),
            'vulnerabilities_by_severity': self._count_vulnerabilities_by_severity(vulnerabilities),
            'vulnerabilities_by_resource': self._count_vulnerabilities_by_resource(vulnerabilities)
        }
        
        return summary
    
    def _count_resources_by_type(self, resources: List[Dict]) -> Dict:
        """Count resources by type"""
        counts = {}
        for resource in resources:
            rtype = resource.get('resource_type', 'Unknown')
            counts[rtype] = counts.get(rtype, 0) + 1
        return counts
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Dict]) -> Dict:
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_vulnerabilities_by_resource(self, vulnerabilities: List[Dict]) -> Dict:
        """Count vulnerabilities by resource type"""
        counts = {}
        for vuln in vulnerabilities:
            rtype = vuln.get('resource_type', 'Unknown')
            counts[rtype] = counts.get(rtype, 0) + 1
        return counts
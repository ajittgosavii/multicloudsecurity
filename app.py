import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import time

from config.aws_config import AWSConfig
from modules.aws_scanner import AWSScanner
from modules.vulnerability_analyzer import VulnerabilityAnalyzer
from modules.remediation_engine import RemediationEngine

# Page configuration
st.set_page_config(
    page_title="AWS Vulnerability Remediation AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #FF4B4B;
        text-align: center;
        margin-bottom: 2rem;
    }
    .severity-high { background-color: #FF4B4B; color: white; padding: 5px; border-radius: 3px; }
    .severity-medium { background-color: #FFA500; color: white; padding: 5px; border-radius: 3px; }
    .severity-low { background-color: #008000; color: white; padding: 5px; border-radius: 3px; }
    .resource-card { 
        border-left: 5px solid #FF4B4B; 
        padding: 10px; 
        margin: 5px 0; 
        background-color: #f0f2f6;
    }
</style>
""", unsafe_allow_html=True)

class VulnerabilityDashboard:
    def __init__(self):
        self.aws_config = AWSConfig()
        self.aws_clients = self.aws_config.get_clients()
        self.scanner = AWSScanner(self.aws_clients)
        self.analyzer = VulnerabilityAnalyzer(self.aws_clients)
        self.remediator = RemediationEngine(self.aws_clients)
        
        # Initialize session state
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = None
        if 'selected_vulnerabilities' not in st.session_state:
            st.session_state.selected_vulnerabilities = []
        if 'remediation_results' not in st.session_state:
            st.session_state.remediation_results = {}
    
    def run_scan(self):
        """Run comprehensive AWS scan"""
        with st.spinner('🔍 Scanning AWS resources...'):
            # Simulate scanning different services
            ec2_results = self.scanner.scan_ec2_instances()
            eks_results = self.scanner.scan_eks_clusters()
            lambda_results = self.scanner.scan_lambda_functions()
            
            # Combine results
            all_resources = ec2_results + eks_results + lambda_results
            
            # Flatten vulnerabilities for easier display
            vulnerability_list = []
            for resource in all_resources:
                if 'vulnerabilities' in resource:
                    for vuln in resource['vulnerabilities']:
                        vuln_data = vuln.copy()
                        vuln_data['resource_id'] = resource['resource_id']
                        vuln_data['resource_type'] = resource['resource_type']
                        vulnerability_list.append(vuln_data)
            
            st.session_state.scan_results = {
                'resources': all_resources,
                'vulnerabilities': vulnerability_list,
                'scan_time': datetime.now().isoformat()
            }
    
    def display_dashboard(self):
        """Main dashboard display"""
        st.markdown('<h1 class="main-header">🛡️ AWS Vulnerability Remediation AI</h1>', unsafe_allow_html=True)
        
        # Sidebar controls
        self.display_sidebar()
        
        # Main content area
        if st.session_state.scan_results is None:
            self.display_welcome()
        else:
            self.display_results()
    
    def display_sidebar(self):
        """Display sidebar controls"""
        with st.sidebar:
            st.header("Controls")
            
            if st.button("🚀 Run Security Scan", use_container_width=True):
                self.run_scan()
                st.rerun()
            
            if st.session_state.scan_results:
                if st.button("🔄 Refresh Scan", use_container_width=True):
                    self.run_scan()
                    st.rerun()
            
            st.header("Filters")
            
            if st.session_state.scan_results:
                vulnerabilities = st.session_state.scan_results['vulnerabilities']
                
                # Resource type filter
                resource_types = list(set([v['resource_type'] for v in vulnerabilities]))
                selected_types = st.multiselect(
                    "Resource Types",
                    resource_types,
                    default=resource_types
                )
                
                # Severity filter
                severities = list(set([v['severity'] for v in vulnerabilities]))
                selected_severities = st.multiselect(
                    "Severity Levels",
                    severities,
                    default=severities
                )
                
                # Vulnerability type filter
                vuln_types = list(set([v['id'] for v in vulnerabilities]))
                selected_vuln_types = st.multiselect(
                    "Vulnerability Types",
                    vuln_types,
                    default=vuln_types
                )
                
                # Apply filters
                filtered_vulns = [
                    v for v in vulnerabilities 
                    if v['resource_type'] in selected_types 
                    and v['severity'] in selected_severities
                    and v['id'] in selected_vuln_types
                ]
                
                st.session_state.filtered_vulnerabilities = filtered_vulns
    
    def display_welcome(self):
        """Display welcome screen"""
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            st.info("""
            ## Welcome to AWS Vulnerability Remediation AI!
            
            This tool helps you:
            - 🔍 **Scan** your AWS resources (EC2, EKS, Lambda) for security vulnerabilities
            - 🤖 **Analyze** vulnerabilities using AI-powered assessment
            - ⚡ **Remediate** issues automatically with one click
            - 📊 **Monitor** your cloud security posture
            
            Click **'Run Security Scan'** in the sidebar to get started!
            """)
            
            # Quick stats placeholder
            st.subheader("Supported Services")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("EC2 Instances", "Vulnerability Scanning", "IMDSv2, Security Groups")
            with col2:
                st.metric("EKS Clusters", "Control Plane", "Logging, Endpoint Security")
            with col3:
                st.metric("Lambda Functions", "Runtime Security", "Permissions, Environment")
    
    def display_results(self):
        """Display scan results and analysis"""
        resources = st.session_state.scan_results['resources']
        vulnerabilities = st.session_state.get('filtered_vulnerabilities', [])
        
        # Summary metrics
        self.display_metrics(resources, vulnerabilities)
        
        # Detailed views
        tab1, tab2, tab3, tab4 = st.tabs([
            "📋 Vulnerabilities", 
            "🔧 Resources", 
            "🤖 AI Analysis", 
            "⚡ Remediation"
        ])
        
        with tab1:
            self.display_vulnerabilities_tab(vulnerabilities)
        
        with tab2:
            self.display_resources_tab(resources)
        
        with tab3:
            self.display_analysis_tab(vulnerabilities)
        
        with tab4:
            self.display_remediation_tab(vulnerabilities)
    
    def display_metrics(self, resources, vulnerabilities):
        """Display summary metrics"""
        col1, col2, col3, col4, col5 = st.columns(5)
        
        total_resources = len(resources)
        total_vulns = len(vulnerabilities)
        high_vulns = len([v for v in vulnerabilities if v['severity'] == 'HIGH'])
        medium_vulns = len([v for v in vulnerabilities if v['severity'] == 'MEDIUM'])
        low_vulns = len([v for v in vulnerabilities if v['severity'] == 'LOW'])
        
        with col1:
            st.metric("Total Resources", total_resources)
        with col2:
            st.metric("Total Vulnerabilities", total_vulns)
        with col3:
            st.metric("High Severity", high_vulns, delta_color="inverse")
        with col4:
            st.metric("Medium Severity", medium_vulns, delta_color="inverse")
        with col5:
            st.metric("Low Severity", low_vulns)
        
        # Severity distribution chart
        if vulnerabilities:
            fig = px.pie(
                names=['High', 'Medium', 'Low'],
                values=[high_vulns, medium_vulns, low_vulns],
                title="Vulnerability Severity Distribution",
                color=['High', 'Medium', 'Low'],
                color_discrete_map={'High':'red', 'Medium':'orange', 'Low':'green'}
            )
            st.plotly_chart(fig, use_container_width=True)
    
    def display_vulnerabilities_tab(self, vulnerabilities):
        """Display vulnerabilities in a detailed table"""
        if not vulnerabilities:
            st.info("No vulnerabilities found matching the current filters.")
            return
        
        # Convert to DataFrame for better display
        vuln_df = pd.DataFrame(vulnerabilities)
        
        # Display expandable details for each vulnerability
        for idx, vuln in enumerate(vulnerabilities):
            with st.expander(f"{vuln['severity']} - {vuln['title']} - {vuln['resource_id']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Resource:** {vuln['resource_type']} - {vuln['resource_id']}")
                    st.write(f"**Severity:** <span class='severity-{vuln["severity"].lower()}'>{vuln['severity']}</span>", unsafe_allow_html=True)
                    st.write(f"**Vulnerability ID:** {vuln['id']}")
                
                with col2:
                    st.write(f"**Description:** {vuln['description']}")
                    st.write(f"**Remediation:** {vuln.get('remediation', 'Not specified')}")
                
                # Select for remediation
                if st.button(f"Select for Remediation", key=f"select_{idx}"):
                    if vuln not in st.session_state.selected_vulnerabilities:
                        st.session_state.selected_vulnerabilities.append(vuln)
                        st.success("Added to remediation queue!")
    
    def display_resources_tab(self, resources):
        """Display resource details"""
        for resource in resources:
            with st.expander(f"{resource['resource_type']} - {resource['resource_id']}"):
                st.json(resource, expanded=False)
    
    def display_analysis_tab(self, vulnerabilities):
        """Display AI-powered analysis"""
        st.header("🤖 AI-Powered Vulnerability Analysis")
        
        if not vulnerabilities:
            st.info("No vulnerabilities to analyze.")
            return
        
        selected_vuln = st.selectbox(
            "Select vulnerability for detailed AI analysis:",
            options=vulnerabilities,
            format_func=lambda x: f"{x['severity']} - {x['title']} - {x['resource_id']}"
        )
        
        if selected_vuln and st.button("Generate AI Analysis"):
            with st.spinner("🤖 AI is analyzing the vulnerability..."):
                # Find the full resource context
                resource_context = next(
                    (r for r in st.session_state.scan_results['resources'] 
                     if r['resource_id'] == selected_vuln['resource_id']),
                    {}
                )
                
                analysis = self.analyzer.analyze_vulnerability(selected_vuln, resource_context)
                
                # Display analysis results
                st.subheader("Risk Assessment")
                st.write(analysis.get('risk_assessment', 'No assessment available'))
                
                st.subheader("Remediation Steps")
                for step in analysis.get('remediation_steps', []):
                    st.write(f"• {step}")
                
                st.subheader("AWS Commands")
                for cmd in analysis.get('aws_commands', []):
                    st.code(cmd, language='bash')
                
                st.subheader("Potential Impact")
                st.write(analysis.get('impact', 'Not specified'))
                
                st.subheader("Verification Steps")
                for step in analysis.get('verification', []):
                    st.write(f"• {step}")
    
    def display_remediation_tab(self, vulnerabilities):
        """Display remediation interface"""
        st.header("⚡ Automated Remediation")
        
        # Show selected vulnerabilities
        selected_vulns = st.session_state.selected_vulnerabilities
        
        if not selected_vulns:
            st.info("No vulnerabilities selected for remediation. Select vulnerabilities from the Vulnerabilities tab.")
            return
        
        st.subheader("Selected for Remediation")
        for idx, vuln in enumerate(selected_vulns):
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.write(f"**{vuln['title']}** - {vuln['resource_id']}")
            with col2:
                st.write(f"`{vuln['severity']}`")
            with col3:
                if st.button("Remove", key=f"remove_{idx}"):
                    st.session_state.selected_vulnerabilities.remove(vuln)
                    st.rerun()
        
        # Bulk remediation
        if st.button("🚀 Remediate All Selected", type="primary"):
            self.execute_bulk_remediation(selected_vulns)
        
        # Show previous remediation results
        if st.session_state.remediation_results:
            st.subheader("Remediation History")
            for result_id, result in st.session_state.remediation_results.items():
                status_color = "🟢" if result['status'] == 'success' else "🔴" if result['status'] == 'error' else "🟡"
                st.write(f"{status_color} {result_id}: {result['message']}")
    
    def execute_bulk_remediation(self, vulnerabilities):
        """Execute remediation for multiple vulnerabilities"""
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, vuln in enumerate(vulnerabilities):
            status_text.text(f"Remediating {vuln['title']}...")
            
            # Find resource context
            resource_context = next(
                (r for r in st.session_state.scan_results['resources'] 
                 if r['resource_id'] == vuln['resource_id']),
                {}
            )
            
            # Get AI analysis for remediation
            analysis = self.analyzer.analyze_vulnerability(vuln, resource_context)
            
            # Execute remediation
            result = self.remediator.remediate_vulnerability(
                vuln['resource_type'],
                vuln['resource_id'],
                vuln,
                analysis
            )
            
            # Store result
            result_id = f"{vuln['resource_id']}_{vuln['id']}"
            st.session_state.remediation_results[result_id] = result
            
            progress_bar.progress((i + 1) / len(vulnerabilities))
        
        status_text.text("Remediation completed!")
        st.success("✅ All selected vulnerabilities have been processed!")

def main():
    # Initialize dashboard
    dashboard = VulnerabilityDashboard()
    dashboard.display_dashboard()

if __name__ == "__main__":
    main()
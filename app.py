import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import time

from config.aws_config import AWSConfig, ALL_REGIONS
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
    /* Header */
    .main-header {
        font-size: 2.4rem;
        font-weight: 700;
        color: #1a1a2e;
        text-align: center;
        margin-bottom: 0.5rem;
        letter-spacing: -0.5px;
    }
    .sub-header {
        text-align: center;
        color: #6c757d;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }

    /* Severity badges */
    .severity-high { background-color: #dc3545; color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
    .severity-medium { background-color: #fd7e14; color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
    .severity-low { background-color: #28a745; color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }

    /* Region badge */
    .region-badge {
        background-color: #232F3E;
        color: #FF9900;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.8em;
        font-weight: 600;
        font-family: monospace;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 8px;
        padding: 12px 16px;
        text-align: center;
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.85rem !important;
        font-weight: 600;
        color: #495057;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.8rem !important;
        font-weight: 700;
        color: #1a1a2e;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px 6px 0 0;
        padding: 8px 20px;
        font-weight: 600;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #f8f9fa;
    }
    section[data-testid="stSidebar"] .stButton > button {
        border-radius: 6px;
        font-weight: 600;
    }

    /* Expanders */
    .streamlit-expanderHeader {
        font-size: 0.95rem;
        font-weight: 500;
    }

    /* Dataframe */
    .stDataFrame {
        border-radius: 8px;
        overflow: hidden;
    }

    /* General text alignment */
    .block-container {
        padding-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)


class VulnerabilityDashboard:
    def __init__(self):
        self.aws_config = AWSConfig()
        # Initialize session state
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = None
        if 'selected_vulnerabilities' not in st.session_state:
            st.session_state.selected_vulnerabilities = []
        if 'remediation_results' not in st.session_state:
            st.session_state.remediation_results = {}

    def run_scan(self, selected_regions):
        """Run comprehensive AWS scan across selected regions"""
        all_resources = []
        scan_errors = []

        progress_bar = st.progress(0)
        status_text = st.empty()

        for i, region in enumerate(selected_regions):
            status_text.text(f"Scanning {region} ({i+1}/{len(selected_regions)})...")
            progress_bar.progress((i) / len(selected_regions))

            try:
                clients = self.aws_config.get_clients(region)
                scanner = AWSScanner(clients, region)

                ec2_results = scanner.scan_ec2_instances()
                all_resources.extend(ec2_results)

                eks_results = scanner.scan_eks_clusters()
                all_resources.extend(eks_results)

                ecs_results = scanner.scan_ecs_clusters()
                all_resources.extend(ecs_results)

                lambda_results = scanner.scan_lambda_functions()
                all_resources.extend(lambda_results)

            except Exception as e:
                scan_errors.append(f"{region}: {str(e)}")

        progress_bar.progress(1.0)
        status_text.text(f"Scan complete! Found {len(all_resources)} resources across {len(selected_regions)} regions.")

        # Flatten vulnerabilities
        vulnerability_list = []
        for resource in all_resources:
            if 'vulnerabilities' in resource:
                for vuln in resource['vulnerabilities']:
                    vuln_data = vuln.copy()
                    vuln_data['resource_id'] = resource['resource_id']
                    vuln_data['resource_type'] = resource['resource_type']
                    vuln_data['region'] = resource.get('region', 'N/A')
                    vuln_data['resource_name'] = resource.get('resource_name', 'N/A')
                    vulnerability_list.append(vuln_data)

        st.session_state.scan_results = {
            'resources': all_resources,
            'vulnerabilities': vulnerability_list,
            'scan_time': datetime.now().isoformat(),
            'regions_scanned': selected_regions,
            'errors': scan_errors,
        }

    def display_dashboard(self):
        """Main dashboard display"""
        st.markdown('<h1 class="main-header">🛡️ AWS Vulnerability Remediation AI</h1>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">Automated multi-region security scanning, AI-powered analysis &amp; one-click remediation</p>', unsafe_allow_html=True)

        # Sidebar controls
        selected_regions = self.display_sidebar()

        # Main content area
        if st.session_state.scan_results is None:
            self.display_welcome()
        else:
            # Show scan errors if any
            errors = st.session_state.scan_results.get('errors', [])
            if errors:
                with st.expander(f"⚠️ {len(errors)} region(s) had scan errors", expanded=False):
                    for err in errors:
                        st.warning(err)
            self.display_results()

    def display_sidebar(self):
        """Display sidebar controls"""
        with st.sidebar:
            st.header("Controls")

            # Region selector
            st.subheader("AWS Regions")
            region_mode = st.radio(
                "Region selection",
                ["All regions", "Select regions"],
                index=1
            )

            if region_mode == "All regions":
                selected_regions = ALL_REGIONS
                st.caption(f"Will scan {len(ALL_REGIONS)} regions")
            else:
                selected_regions = st.multiselect(
                    "Choose regions to scan",
                    ALL_REGIONS,
                    default=['us-east-1', 'us-west-2']
                )

            st.divider()

            if st.button("🚀 Run Security Scan", use_container_width=True):
                if selected_regions:
                    self.run_scan(selected_regions)
                    st.rerun()
                else:
                    st.error("Please select at least one region.")

            if st.session_state.scan_results:
                scanned = st.session_state.scan_results.get('regions_scanned', [])
                st.caption(f"Last scan: {len(scanned)} region(s) at {st.session_state.scan_results.get('scan_time', 'N/A')[:19]}")

                if st.button("🔄 Refresh Scan", use_container_width=True):
                    self.run_scan(selected_regions)
                    st.rerun()

            st.divider()
            st.header("Filters")

            if st.session_state.scan_results:
                vulnerabilities = st.session_state.scan_results['vulnerabilities']

                if vulnerabilities:
                    # Region filter
                    regions = sorted(set([v.get('region', 'N/A') for v in vulnerabilities]))
                    selected_region_filter = st.multiselect("Regions", regions, default=regions)

                    # Resource type filter
                    resource_types = sorted(set([v['resource_type'] for v in vulnerabilities]))
                    selected_types = st.multiselect("Resource Types", resource_types, default=resource_types)

                    # Severity filter
                    severities = list(set([v['severity'] for v in vulnerabilities]))
                    selected_severities = st.multiselect("Severity Levels", severities, default=severities)

                    # Vulnerability type filter
                    vuln_types = sorted(set([v['id'] for v in vulnerabilities]))
                    selected_vuln_types = st.multiselect("Vulnerability Types", vuln_types, default=vuln_types)

                    # Apply filters
                    filtered_vulns = [
                        v for v in vulnerabilities
                        if v['resource_type'] in selected_types
                        and v['severity'] in selected_severities
                        and v['id'] in selected_vuln_types
                        and v.get('region', 'N/A') in selected_region_filter
                    ]
                    st.session_state.filtered_vulnerabilities = filtered_vulns
                else:
                    st.session_state.filtered_vulnerabilities = []

        return selected_regions

    def display_welcome(self):
        """Display welcome screen"""
        st.markdown("---")
        col1, col2, col3 = st.columns([1, 3, 1])

        with col2:
            st.markdown("""
            ### Getting Started

            1. **Select regions** in the sidebar (or choose "All regions")
            2. Click **Run Security Scan** to begin
            3. Review vulnerabilities, run AI analysis, and remediate

            **Supported services:** EC2, EKS, ECS, Lambda
            """)

        st.markdown("---")
        st.markdown("#### Scan Coverage")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("**🖥️ EC2 Instances**")
            st.caption("Public IPs, Security Groups, IMDSv2, VPC placement")
        with col2:
            st.markdown("**☸️ EKS Clusters**")
            st.caption("Control plane logging, endpoint access, KMS encryption")
        with col3:
            st.markdown("**📦 ECS Clusters**")
            st.caption("Container Insights, capacity providers, exec logging")
        with col4:
            st.markdown("**λ Lambda Functions**")
            st.caption("IAM permissions, environment variables, VPC config")

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
        col1, col2, col3, col4, col5, col6 = st.columns(6)

        total_resources = len(resources)
        total_vulns = len(vulnerabilities)
        high_vulns = len([v for v in vulnerabilities if v['severity'] == 'HIGH'])
        medium_vulns = len([v for v in vulnerabilities if v['severity'] == 'MEDIUM'])
        low_vulns = len([v for v in vulnerabilities if v['severity'] == 'LOW'])
        regions_scanned = len(st.session_state.scan_results.get('regions_scanned', []))

        with col1:
            st.metric("Regions Scanned", regions_scanned)
        with col2:
            st.metric("Total Resources", total_resources)
        with col3:
            st.metric("Total Vulnerabilities", total_vulns)
        with col4:
            st.metric("High Severity", high_vulns, delta_color="inverse")
        with col5:
            st.metric("Medium Severity", medium_vulns, delta_color="inverse")
        with col6:
            st.metric("Low Severity", low_vulns)

        if vulnerabilities:
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                fig = px.pie(
                    names=['High', 'Medium', 'Low'],
                    values=[high_vulns, medium_vulns, low_vulns],
                    title="Vulnerability Severity Distribution",
                    color=['High', 'Medium', 'Low'],
                    color_discrete_map={'High': 'red', 'Medium': 'orange', 'Low': 'green'}
                )
                st.plotly_chart(fig, use_container_width=True)

            with chart_col2:
                # Resources by region chart
                region_counts = {}
                for r in resources:
                    reg = r.get('region', 'Unknown')
                    region_counts[reg] = region_counts.get(reg, 0) + 1

                if region_counts:
                    fig2 = px.bar(
                        x=list(region_counts.keys()),
                        y=list(region_counts.values()),
                        title="Resources by Region",
                        labels={'x': 'Region', 'y': 'Count'},
                        color=list(region_counts.values()),
                        color_continuous_scale='Oranges'
                    )
                    fig2.update_layout(showlegend=False)
                    st.plotly_chart(fig2, use_container_width=True)

    def display_vulnerabilities_tab(self, vulnerabilities):
        """Display vulnerabilities in a detailed table"""
        if not vulnerabilities:
            st.info("No vulnerabilities found matching the current filters.")
            return

        # Summary table
        vuln_df = pd.DataFrame([{
            'Region': v.get('region', 'N/A'),
            'Resource Type': v['resource_type'],
            'Resource ID': v['resource_id'],
            'Severity': v['severity'],
            'Vulnerability': v['title'],
        } for v in vulnerabilities])
        st.dataframe(vuln_df, use_container_width=True, hide_index=True)

        st.divider()

        # Expandable details
        for idx, vuln in enumerate(vulnerabilities):
            region_badge = f"<span class='region-badge'>{vuln.get('region', 'N/A')}</span>"
            with st.expander(f"{vuln['severity']} | {vuln.get('region', '')} | {vuln['resource_type']} - {vuln['title']} - {vuln['resource_id']}"):
                col1, col2 = st.columns(2)

                with col1:
                    st.write(f"**Resource:** {vuln['resource_type']} - {vuln['resource_id']}")
                    st.write(f"**Region:** {vuln.get('region', 'N/A')}")
                    st.write(f"**Severity:** {vuln['severity']}")
                    st.write(f"**Vulnerability ID:** {vuln['id']}")

                with col2:
                    st.write(f"**Description:** {vuln['description']}")
                    st.write(f"**Remediation:** {vuln.get('remediation', 'Not specified')}")

                if st.button("Select for Remediation", key=f"select_{idx}"):
                    if vuln not in st.session_state.selected_vulnerabilities:
                        st.session_state.selected_vulnerabilities.append(vuln)
                        st.success("Added to remediation queue!")

    def display_resources_tab(self, resources):
        """Display resource details"""
        if not resources:
            st.info("No resources found.")
            return

        # Group by resource type
        by_type = {}
        for r in resources:
            rtype = r.get('resource_type', 'Unknown')
            by_type.setdefault(rtype, []).append(r)

        for rtype, items in sorted(by_type.items()):
            st.subheader(f"{rtype} ({len(items)})")
            for resource in items:
                label = f"{resource.get('region', 'N/A')} | {resource.get('resource_id', 'Unknown')}"
                if resource.get('resource_name') and resource['resource_name'] != 'N/A':
                    label += f" ({resource['resource_name']})"
                vuln_count = len(resource.get('vulnerabilities', []))
                label += f" - {vuln_count} vulnerabilities"

                with st.expander(label):
                    display_data = {k: v for k, v in resource.items() if k != 'vulnerabilities'}
                    st.json(display_data, expanded=False)

    def display_analysis_tab(self, vulnerabilities):
        """Display AI-powered analysis"""
        st.header("🤖 AI-Powered Vulnerability Analysis")

        if not vulnerabilities:
            st.info("No vulnerabilities to analyze.")
            return

        selected_vuln = st.selectbox(
            "Select vulnerability for detailed AI analysis:",
            options=vulnerabilities,
            format_func=lambda x: f"{x.get('region', '')} | {x['severity']} - {x['title']} - {x['resource_id']}"
        )

        if selected_vuln and st.button("Generate AI Analysis"):
            with st.spinner("🤖 AI is analyzing the vulnerability..."):
                resource_context = next(
                    (r for r in st.session_state.scan_results['resources']
                     if r['resource_id'] == selected_vuln['resource_id']),
                    {}
                )

                # Get clients for the resource's region
                region = selected_vuln.get('region', self.aws_config.region)
                clients = self.aws_config.get_clients(region)
                analyzer = VulnerabilityAnalyzer(clients)
                analysis = analyzer.analyze_vulnerability(selected_vuln, resource_context)

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

        selected_vulns = st.session_state.selected_vulnerabilities

        if not selected_vulns:
            st.info("No vulnerabilities selected for remediation. Select vulnerabilities from the Vulnerabilities tab.")
            return

        st.subheader("Selected for Remediation")
        for idx, vuln in enumerate(selected_vulns):
            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
            with col1:
                st.write(f"**{vuln['title']}** - {vuln['resource_id']}")
            with col2:
                st.write(f"`{vuln.get('region', 'N/A')}`")
            with col3:
                st.write(f"`{vuln['severity']}`")
            with col4:
                if st.button("Remove", key=f"remove_{idx}"):
                    st.session_state.selected_vulnerabilities.remove(vuln)
                    st.rerun()

        if st.button("🚀 Remediate All Selected", type="primary"):
            self.execute_bulk_remediation(selected_vulns)

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
            status_text.text(f"Remediating {vuln['title']} in {vuln.get('region', 'N/A')}...")

            resource_context = next(
                (r for r in st.session_state.scan_results['resources']
                 if r['resource_id'] == vuln['resource_id']),
                {}
            )

            region = vuln.get('region', self.aws_config.region)
            clients = self.aws_config.get_clients(region)
            analyzer = VulnerabilityAnalyzer(clients)
            remediator = RemediationEngine(clients)

            analysis = analyzer.analyze_vulnerability(vuln, resource_context)

            result = remediator.remediate_vulnerability(
                vuln['resource_type'],
                vuln['resource_id'],
                vuln,
                analysis
            )

            result_id = f"{vuln.get('region', 'N/A')}/{vuln['resource_id']}_{vuln['id']}"
            st.session_state.remediation_results[result_id] = result

            progress_bar.progress((i + 1) / len(vulnerabilities))

        status_text.text("Remediation completed!")
        st.success("✅ All selected vulnerabilities have been processed!")


def main():
    dashboard = VulnerabilityDashboard()
    dashboard.display_dashboard()


if __name__ == "__main__":
    main()

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

from src.cloud import AWSConnector, MultiRegionScanner, ALL_REGIONS
from src.analysis import AISecurityAnalyzer
from src.remediation import RemediationExecutor

# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Multi-Cloud Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .app-title {
        font-size: 2.2rem; font-weight: 700; color: #1a1a2e;
        text-align: center; margin-bottom: 0.25rem; letter-spacing: -0.5px;
    }
    .app-subtitle {
        text-align: center; color: #6c757d; font-size: 0.95rem; margin-bottom: 1.5rem;
    }
    .sev-high   { background:#dc3545; color:#fff; padding:3px 10px; border-radius:12px; font-size:.8em; font-weight:600; }
    .sev-medium { background:#fd7e14; color:#fff; padding:3px 10px; border-radius:12px; font-size:.8em; font-weight:600; }
    .sev-low    { background:#28a745; color:#fff; padding:3px 10px; border-radius:12px; font-size:.8em; font-weight:600; }
    .region-tag {
        background:#232F3E; color:#FF9900; padding:2px 8px; border-radius:4px;
        font-size:.8em; font-weight:600; font-family:monospace;
    }
    [data-testid="stMetric"] {
        background:#f8f9fa; border:1px solid #e9ecef; border-radius:8px;
        padding:12px 16px; text-align:center;
    }
    [data-testid="stMetricLabel"]  { font-size:.85rem!important; font-weight:600; color:#495057; text-transform:uppercase; letter-spacing:.5px; }
    [data-testid="stMetricValue"]  { font-size:1.8rem!important; font-weight:700; color:#1a1a2e; }
    .stTabs [data-baseweb="tab-list"] { gap:8px; }
    .stTabs [data-baseweb="tab"]      { border-radius:6px 6px 0 0; padding:8px 20px; font-weight:600; }
    section[data-testid="stSidebar"] { background:#f8f9fa; }
    section[data-testid="stSidebar"] .stButton>button { border-radius:6px; font-weight:600; }
    .block-container { padding-top:2rem; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class SecurityDashboard:

    def __init__(self):
        self.connector = AWSConnector()
        for key in ('scan_results', 'selected_vulns', 'remediation_log'):
            if key not in st.session_state:
                st.session_state[key] = None if key == 'scan_results' else ([] if key == 'selected_vulns' else {})

    # ---- sidebar --------------------------------------------------------

    def _sidebar(self):
        with st.sidebar:
            st.header("Scan Settings")

            mode = st.radio("Region scope", ["Select regions", "All regions"], index=0)
            if mode == "All regions":
                regions = ALL_REGIONS
                st.caption(f"{len(regions)} regions selected")
            else:
                regions = st.multiselect("Regions", ALL_REGIONS, default=['us-east-1', 'us-west-2'])

            st.divider()

            # Credential status
            if self.connector._access_key:
                masked = self.connector._access_key[:4] + "****"
                st.success(f"AWS credentials loaded ({masked})")
            else:
                st.error("AWS credentials not found. Add them in Settings → Secrets.")

            if st.button("🚀 Run Scan", use_container_width=True):
                if not regions:
                    st.error("Select at least one region.")
                else:
                    self._run_scan(regions)
                    st.rerun()

            if st.session_state.scan_results:
                meta = st.session_state.scan_results
                st.caption(f"Last scan: {len(meta['regions'])} region(s) · {meta['timestamp'][:19]}")
                if st.button("🔄 Refresh", use_container_width=True):
                    self._run_scan(regions)
                    st.rerun()

            st.divider()
            st.header("Filters")
            filtered = self._apply_filters()
            st.session_state['_filtered'] = filtered

        return regions

    def _apply_filters(self):
        if not st.session_state.scan_results:
            return []
        vulns = st.session_state.scan_results['vulnerabilities']
        if not vulns:
            return []

        all_regions = sorted({v.get('region', 'N/A') for v in vulns})
        all_types = sorted({v['resource_type'] for v in vulns})
        all_sevs = sorted({v['severity'] for v in vulns})

        sel_regions = st.multiselect("Region", all_regions, default=all_regions)
        sel_types = st.multiselect("Service", all_types, default=all_types)
        sel_sevs = st.multiselect("Severity", all_sevs, default=all_sevs)

        return [v for v in vulns
                if v.get('region') in sel_regions
                and v['resource_type'] in sel_types
                and v['severity'] in sel_sevs]

    # ---- scan -----------------------------------------------------------

    def _run_scan(self, regions):
        scanner = MultiRegionScanner(self.connector)
        progress = st.progress(0)
        status = st.empty()

        def on_progress(region, idx, total):
            status.text(f"Scanning {region}  ({idx + 1}/{total})")
            progress.progress(idx / total)

        resources, errors = scanner.scan(regions, on_progress=on_progress)
        progress.progress(1.0)
        status.text(f"Done — {len(resources)} resources across {len(regions)} regions")

        vuln_list = []
        for r in resources:
            for v in r.get('vulnerabilities', []):
                entry = v.copy()
                entry['resource_id'] = r['resource_id']
                entry['resource_type'] = r['resource_type']
                entry['region'] = r.get('region', 'N/A')
                entry['resource_name'] = r.get('resource_name', 'N/A')
                vuln_list.append(entry)

        st.session_state.scan_results = {
            'resources': resources,
            'vulnerabilities': vuln_list,
            'timestamp': datetime.now().isoformat(),
            'regions': regions,
            'errors': errors,
        }

    # ---- main layout ----------------------------------------------------

    def render(self):
        st.markdown('<h1 class="app-title">🛡️ Multi-Cloud Security Scanner</h1>', unsafe_allow_html=True)
        st.markdown('<p class="app-subtitle">Automated multi-region vulnerability scanning · AI-powered analysis · One-click remediation</p>', unsafe_allow_html=True)

        self._sidebar()

        if not st.session_state.scan_results:
            self._welcome()
            return

        errors = st.session_state.scan_results.get('errors', [])
        if errors:
            with st.expander(f"⚠️ {len(errors)} region(s) had errors", expanded=False):
                for e in errors:
                    st.warning(e)

        vulns = st.session_state.get('_filtered', [])
        resources = st.session_state.scan_results['resources']

        self._metrics(resources, vulns)

        tab1, tab2, tab3, tab4 = st.tabs(["📋 Vulnerabilities", "🔧 Resources", "🤖 AI Analysis", "⚡ Remediation"])
        with tab1:
            self._tab_vulnerabilities(vulns)
        with tab2:
            self._tab_resources(resources)
        with tab3:
            self._tab_analysis(vulns)
        with tab4:
            self._tab_remediation(vulns)

    # ---- welcome --------------------------------------------------------

    def _welcome(self):
        st.markdown("---")
        _, center, _ = st.columns([1, 3, 1])
        with center:
            st.markdown("""
### Getting Started
1. **Select regions** in the sidebar (or scan all)
2. Click **Run Scan**
3. Review findings, run AI analysis, and remediate
""")
        st.markdown("---")
        st.markdown("#### Scan Coverage")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown("**🖥️ EC2 Instances**")
            st.caption("Public IPs · Security Groups · IMDSv2 · VPC placement")
        with c2:
            st.markdown("**☸️ EKS Clusters**")
            st.caption("Control plane logging · Endpoint access · KMS encryption")
        with c3:
            st.markdown("**📦 ECS Clusters**")
            st.caption("Container Insights · Capacity providers · Exec logging")
        with c4:
            st.markdown("**λ Lambda Functions**")
            st.caption("IAM permissions · Environment variables · VPC config")

    # ---- metrics --------------------------------------------------------

    def _metrics(self, resources, vulns):
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        high = sum(1 for v in vulns if v['severity'] == 'HIGH')
        med = sum(1 for v in vulns if v['severity'] == 'MEDIUM')
        low = sum(1 for v in vulns if v['severity'] == 'LOW')
        c1.metric("Regions", len(st.session_state.scan_results['regions']))
        c2.metric("Resources", len(resources))
        c3.metric("Findings", len(vulns))
        c4.metric("High", high, delta_color="inverse")
        c5.metric("Medium", med, delta_color="inverse")
        c6.metric("Low", low)

        if not vulns:
            return

        left, right = st.columns(2)
        with left:
            fig = px.pie(names=['High', 'Medium', 'Low'], values=[high, med, low],
                         title="Severity Breakdown",
                         color_discrete_map={'High': '#dc3545', 'Medium': '#fd7e14', 'Low': '#28a745'})
            st.plotly_chart(fig, use_container_width=True)
        with right:
            rc = {}
            for r in resources:
                rc[r.get('region', '?')] = rc.get(r.get('region', '?'), 0) + 1
            fig2 = px.bar(x=list(rc.keys()), y=list(rc.values()),
                          title="Resources by Region",
                          labels={'x': 'Region', 'y': 'Count'},
                          color=list(rc.values()), color_continuous_scale='Oranges')
            fig2.update_layout(showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)

    # ---- tabs -----------------------------------------------------------

    def _tab_vulnerabilities(self, vulns):
        if not vulns:
            st.info("No findings match the current filters.")
            return

        df = pd.DataFrame([{
            'Region': v.get('region'),
            'Service': v['resource_type'],
            'Resource': v['resource_id'],
            'Severity': v['severity'],
            'Finding': v['title'],
        } for v in vulns])
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.divider()

        for i, v in enumerate(vulns):
            with st.expander(f"{v['severity']} · {v.get('region','')} · {v['resource_type']} — {v['title']} — {v['resource_id']}"):
                a, b = st.columns(2)
                a.write(f"**Resource:** {v['resource_type']} / {v['resource_id']}")
                a.write(f"**Region:** {v.get('region')}")
                a.write(f"**Severity:** {v['severity']}")
                a.write(f"**ID:** {v['id']}")
                b.write(f"**Description:** {v['description']}")
                b.write(f"**Remediation:** {v.get('remediation', '—')}")
                if st.button("Add to remediation queue", key=f"sel_{i}"):
                    if v not in st.session_state.selected_vulns:
                        st.session_state.selected_vulns.append(v)
                        st.success("Added!")

    def _tab_resources(self, resources):
        if not resources:
            st.info("No resources found.")
            return
        by_type = {}
        for r in resources:
            by_type.setdefault(r.get('resource_type', '?'), []).append(r)
        for rtype in sorted(by_type):
            items = by_type[rtype]
            st.subheader(f"{rtype}  ({len(items)})")
            for r in items:
                name = r.get('resource_name', '')
                label = f"{r.get('region')} · {r['resource_id']}"
                if name and name != 'N/A':
                    label += f" ({name})"
                vc = len(r.get('vulnerabilities', []))
                label += f" — {vc} finding{'s' if vc != 1 else ''}"
                with st.expander(label):
                    st.json({k: v for k, v in r.items() if k != 'vulnerabilities'}, expanded=False)

    def _tab_analysis(self, vulns):
        st.header("🤖 AI-Powered Analysis")
        if not vulns:
            st.info("No findings to analyze.")
            return

        sel = st.selectbox("Select finding:",
                           vulns,
                           format_func=lambda v: f"{v.get('region')} · {v['severity']} — {v['title']} — {v['resource_id']}")
        if sel and st.button("Generate Analysis"):
            with st.spinner("Analyzing with Bedrock…"):
                ctx = next((r for r in st.session_state.scan_results['resources']
                            if r['resource_id'] == sel['resource_id']), {})
                region = sel.get('region', self.connector.default_region)
                clients = self.connector.clients(region)
                analyzer = AISecurityAnalyzer(clients)
                result = analyzer.analyze(sel, ctx)

                st.subheader("Risk Assessment")
                st.write(result.get('risk_assessment', '—'))
                st.subheader("Remediation Steps")
                for s in result.get('remediation_steps', []):
                    st.write(f"• {s}")
                st.subheader("AWS Commands")
                for c in result.get('aws_commands', []):
                    st.code(c, language='bash')
                st.subheader("Impact")
                st.write(result.get('impact', '—'))
                st.subheader("Verification")
                for s in result.get('verification', []):
                    st.write(f"• {s}")

    def _tab_remediation(self, vulns):
        st.header("⚡ Remediation")
        selected = st.session_state.selected_vulns
        if not selected:
            st.info("Select findings from the Vulnerabilities tab to add them here.")
            return

        st.subheader("Remediation Queue")
        for i, v in enumerate(selected):
            c1, c2, c3, c4 = st.columns([3, 1, 1, 1])
            c1.write(f"**{v['title']}** — {v['resource_id']}")
            c2.write(f"`{v.get('region')}`")
            c3.write(f"`{v['severity']}`")
            if c4.button("Remove", key=f"rm_{i}"):
                st.session_state.selected_vulns.remove(v)
                st.rerun()

        if st.button("🚀 Remediate All", type="primary"):
            bar = st.progress(0)
            msg = st.empty()
            for i, v in enumerate(selected):
                msg.text(f"Remediating {v['title']} in {v.get('region')}…")
                region = v.get('region', self.connector.default_region)
                clients = self.connector.clients(region)
                analyzer = AISecurityAnalyzer(clients)
                executor = RemediationExecutor(clients)
                ctx = next((r for r in st.session_state.scan_results['resources']
                            if r['resource_id'] == v['resource_id']), {})
                analysis = analyzer.analyze(v, ctx)
                result = executor.remediate(v['resource_type'], v['resource_id'], v, analysis)
                key = f"{v.get('region')}/{v['resource_id']}_{v['id']}"
                st.session_state.remediation_log[key] = result
                bar.progress((i + 1) / len(selected))
            msg.text("Done!")
            st.success("✅ All selected findings have been processed.")

        if st.session_state.remediation_log:
            st.subheader("History")
            for rid, res in st.session_state.remediation_log.items():
                icon = {"success": "🟢", "error": "🔴"}.get(res['status'], "🟡")
                st.write(f"{icon} {rid}: {res['message']}")


# ---------------------------------------------------------------------------

def main():
    SecurityDashboard().render()

if __name__ == "__main__":
    main()

import streamlit as st
import duckdb
import pandas as pd
from pathlib import Path
import json

# Page configuration
st.set_page_config(
    page_title="The Gatekeeper: Sovereign Telemetry",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = str(BASE_DIR / "gatekeeper_audit.duckdb")

st.title("🛡️ The Gatekeeper — Sovereign VDR Telemetry & Audit Dashboard")
st.markdown("Compliance-first airlock observability, PII redaction metrics, and immutable MCP access tracing.")

def load_data():
    if not Path(DB_PATH).exists():
        return None, None, None
    
    conn = duckdb.connect(DB_PATH, read_only=True)
    try:
        audit_df = conn.execute("SELECT * FROM audit_logs").fetchdf()
    except Exception:
        audit_df = pd.DataFrame()

    try:
        diag_df = conn.execute("SELECT * FROM pre_flight_diagnostics").fetchdf()
    except Exception:
        diag_df = pd.DataFrame()

    try:
        mcp_df = conn.execute("SELECT * FROM mcp_access_logs").fetchdf()
    except Exception:
        mcp_df = pd.DataFrame()

    conn.close()
    return audit_df, diag_df, mcp_df

audit_df, diag_df, mcp_df = load_data()

if audit_df is None or audit_df.empty:
    st.warning("⚠️ No audit ledger found or ledger is empty. Run `python pipeline.py` first to process intake files.")
else:
    # --- TOP-LEVEL METRICS ---
    col1, col2, col3, col4 = st.columns(4)
    
    total_files = len(audit_df)
    successful_files = len(audit_df[audit_df['status'].str.startswith("SUCCESS", na=False)])
    quarantined_files = len(audit_df[audit_df['status'].str.startswith("QUARANTINED", na=False)])
    
    total_tokens_before = audit_df['tokens_before'].sum() if 'tokens_before' in audit_df else 0
    total_tokens_after = audit_df['tokens_after'].sum() if 'tokens_after' in audit_df else 0
    avg_savings = round(((total_tokens_before - total_tokens_after) / max(total_tokens_before, 1)) * 100, 2)

    col1.metric("Total Intake Files", total_files)
    col2.metric("Successfully Zoned", successful_files, delta=f"{successful_files} secured")
    col3.metric("Quarantined (Fail-Closed)", quarantined_files, delta_color="inverse")
    col4.metric("LLM Token Economy Savings", f"{avg_savings}%", delta=f"{total_tokens_before:,} -> {total_tokens_after:,} tokens")

    st.markdown("---")

    # --- TABS FOR DIFFERENT AUDIT VIEWS ---
    tab1, tab2, tab3 = st.tabs(["📊 Processing Audit Logs", "🔍 Pre-Flight PII Diagnostics", "🤖 MCP Cloud Agent Trace Logs"])

    with tab1:
        st.subheader("Pipeline Execution & Functional Zoning Records")
        st.dataframe(audit_df, width="stretch")

    with tab2:
        st.subheader("Pre-Flight Intake PII Detection & Risk Analysis")
        if not diag_df.empty:
            st.dataframe(diag_df, width="stretch")
            
            # Aggregate PII Breakdown
            if 'pii_breakdown_json' in diag_df.columns:
                all_pii = {}
                for json_str in diag_df['pii_breakdown_json']:
                    try:
                        breakdown = json.loads(json_str)
                        for k, v in breakdown.items():
                            all_pii[k] = all_pii.get(k, 0) + v
                    except Exception:
                        pass
                
                if all_pii:
                    st.markdown("### Total Redacted Entities by Type")
                    pii_summary_df = pd.DataFrame(list(all_pii.items()), columns=["Entity Type", "Count"])
                    st.bar_chart(pii_summary_df.set_index("Entity Type"))
        else:
            st.info("No pre-flight diagnostics logged yet.")

    with tab3:
        st.subheader("Immutable MCP Access Trace Ledger (`mcp_access_logs`)")
        if not mcp_df.empty:
            st.dataframe(mcp_df, width="stretch")
        else:
            st.info("No external MCP cloud agent access events recorded yet.")

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.header("Sovereign Controls")
    if st.button("🔄 Refresh Telemetry"):
        st.rerun()
    st.markdown("---")
    st.markdown("**Status:** Air-Gapped / Secure")
    st.markdown("**Compliance:** POPIA / GDPR Ready")
import streamlit as st
import duckdb
import pandas as pd
import json
import os

st.set_page_config(
    page_title="The Gatekeeper — Sovereign Audit & Telemetry",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ The Gatekeeper: Local Operational Audit Ledger")
st.markdown("**Zero-Egress Perimeter Telemetry** — Air-gapped visual monitoring console & VDR compliance tracker.")

DB_PATH = "gatekeeper_audit.duckdb"

if not os.path.exists(DB_PATH):
    st.warning("⚠️ Audit database (`gatekeeper_audit.duckdb`) not found. Run `python pipeline.py` first.")
else:
    try:
        conn = duckdb.connect(DB_PATH, read_only=True)
        tables = [t[0] for t in conn.execute("SHOW TABLES").fetchall()]
        
        if "audit_logs" in tables:
            df_logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC").df()
            
            # Interactive Filters for VDR Folder & File Format
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                if 'vdr_folder' in df_logs.columns:
                    folders = ["All VDR Folders"] + sorted(df_logs['vdr_folder'].dropna().unique().tolist())
                    sel_folder = st.selectbox("Filter by VDR Folder Hierarchy", folders)
                    if sel_folder != "All VDR Folders":
                        df_logs = df_logs[df_logs['vdr_folder'] == sel_folder]
            with col_f2:
                df_logs['file_format'] = df_logs['original_filename'].apply(
                    lambda x: f".{x.split('.')[-1].lower()}" if '.' in str(x) else 'unknown'
                )
                formats = ["All Formats"] + sorted(df_logs['file_format'].unique().tolist())
                sel_fmt = st.selectbox("Filter by File Format", formats)
                if sel_fmt != "All Formats":
                    df_logs = df_logs[df_logs['file_format'] == sel_fmt]

            # Top-Level Executive Metric Cards
            total_processed = len(df_logs[df_logs['status'].str.startswith('SUCCESS')]) if 'status' in df_logs.columns else len(df_logs)
            quarantined = len(df_logs[df_logs['status'].str.startswith('QUARANTINED')]) if 'status' in df_logs.columns else 0
            total_pii = int(df_logs['entities_redacted_count'].sum()) if 'entities_redacted_count' in df_logs.columns else 0
            tok_before = int(df_logs['tokens_before'].sum()) if 'tokens_before' in df_logs.columns else 0
            tok_after = int(df_logs['tokens_after'].sum()) if 'tokens_after' in df_logs.columns else 0
            opt_pct = ((tok_before - tok_after) / tok_before * 100) if tok_before > 0 else 0.0

            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Files Processed", total_processed)
            c2.metric("Quarantined (Fail-Closed)", quarantined)
            c3.metric("PII Entities Redacted", total_pii)
            c4.metric("Model-Aware Tokens", f"{tok_before:,} → {tok_after:,}", f"{opt_pct:.1f}% optimisation")
            c5.metric("Egress Leak Risk", "0.0% (Air-Gapped)")

            st.markdown("---")
            
            # Side-by-Side Detailed Breakdown Section
            col_left, col_right = st.columns(2)
            
            with col_left:
                st.subheader("📦 Pre-Flight Census Breakdown")
                fmt_counts = df_logs['file_format'].value_counts().reset_index()
                fmt_counts.columns = ['File Format', 'Count']
                st.dataframe(fmt_counts, use_container_width=True, hide_index=True)

            with col_right:
                st.subheader("🚨 Pre-Flight PII Risk Distribution")
                if "pre_flight_diagnostics" in tables:
                    df_diag = conn.execute("SELECT pii_breakdown_json FROM pre_flight_diagnostics").df()
                    pii_totals = {}
                    for raw_json in df_diag['pii_breakdown_json'].dropna():
                        for k, v in json.loads(raw_json).items():
                            pii_totals[k] = pii_totals.get(k, 0) + v
                    if pii_totals:
                        df_pii = pd.DataFrame(list(pii_totals.items()), columns=['Entity Type', 'Total Redacted'])
                        st.dataframe(df_pii, use_container_width=True, hide_index=True)
                    else:
                        st.info("No PII risk entities recorded in current run.")

            # Dedicated Pre-Flight Diagnostics Telemetry Table
            if "pre_flight_diagnostics" in tables:
                st.markdown("---")
                st.subheader("🔍 Pre-Flight File Diagnostics & Sheet Profiler")
                df_full_diag = conn.execute("SELECT run_id, timestamp, original_filename, file_format, sheet_count, raw_tokens, total_pii_detected FROM pre_flight_diagnostics ORDER BY timestamp DESC").df()
                st.dataframe(df_full_diag, use_container_width=True, hide_index=True)

            st.markdown("---")
            st.subheader("📋 Local Operational Audit & Transformation Ledger")
            st.dataframe(df_logs, use_container_width=True, hide_index=True)
        else:
            st.info(f"Tables found: {tables}. Run `python pipeline.py` to populate audit logs.")
        conn.close()
    except Exception as e:
        st.error(f"Error reading local DuckDB ledger: {e}")

st.markdown("---")
st.caption("The Gatekeeper MVP 1 | Sovereign Data Sanitization & Airlock Middleware")
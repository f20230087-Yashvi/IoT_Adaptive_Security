"""Interactive dashboard. Run with:  streamlit run dashboard.py"""
from pathlib import Path

import streamlit as st

from iot_twin.data import load_dataset
from iot_twin.evaluate import evaluate_all, rank_policies
from iot_twin.twin import DigitalTwin

st.set_page_config(page_title="IoT Digital Twin Security Evaluator", layout="wide")
st.title("Digital Twin-Based Adaptive Security Evaluation for IoT Networks")
st.caption("Flow-level research prototype. Simulated QoS values must not be reported as real measurements.")

uploaded = st.file_uploader("Upload a traffic CSV (must include a label column)", type=["csv"])
label_col = st.text_input("Label column name (leave blank to auto-detect)", value="")
attack_values = st.text_input("Attack label values (comma-separated, optional)", value="")
weight = st.slider("Security importance weight", 0.0, 1.0, 0.5, 0.05)

try:
    if uploaded:
        path = Path("outputs/uploaded_input.csv")
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(uploaded.getvalue())
        df = load_dataset(str(path), label_col or None, attack_values or None)
    else:
        st.info("No file uploaded: using synthetic demonstration traffic.")
        df = load_dataset()
except ValueError as e:
    st.error(str(e))
    st.stop()

twin = DigitalTwin(df)
metrics, _ = evaluate_all(twin.replay())
ranked = rank_policies(metrics, weight)
snap = twin.snapshot()

st.subheader("Traffic snapshot")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Devices", snap["devices"])
c2.metric("Flow records", snap["flow_count"])
c3.metric("Attack flows", snap["attack_flow_count"])
c4.metric("Benign flows", snap["benign_flow_count"])

st.subheader("Recommended policy under selected weight")
st.success(f"{ranked.iloc[0]['policy']} — combined score {ranked.iloc[0]['combined_score']:.3f}")
st.dataframe(ranked)

st.subheader("Policy comparison")
st.dataframe(metrics)
st.bar_chart(metrics.set_index("policy")[["attack_reduction_pct"]])
st.bar_chart(metrics.set_index("policy")[[
    "benign_latency_ms_simulated", "benign_packet_loss_pct_simulated", "legitimate_traffic_disruption_pct"]])
st.download_button("Download metrics CSV", metrics.to_csv(index=False), "policy_metrics.csv", "text/csv")

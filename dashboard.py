"""Interactive dashboard. Run with:  streamlit run dashboard.py"""
from pathlib import Path

import streamlit as st

from iot_twin.data import load_dataset
from iot_twin.evaluate import evaluate_all, rank_policies
from iot_twin.twin import DigitalTwin

DATA_DIR = Path("data")
UPLOAD_PATH = Path("outputs/uploaded_input.csv")

st.set_page_config(page_title="IoT Digital Twin Security Evaluator", layout="wide")
st.title("Digital Twin-Based Adaptive Security Evaluation for IoT Networks")
st.caption("Flow-level research prototype. Simulated QoS values must not be reported as real measurements.")


@st.cache_data(show_spinner="Loading traffic…")
def load_cached(path, label_col, attack_values, max_rows, file_stamp):
    # file_stamp (size + modified time) makes the cache reload if the file changes.
    return load_dataset(path, label_col, attack_values, max_rows)


@st.cache_data(show_spinner="Running the Digital Twin experiment…")
def evaluate_cached(df):
    return evaluate_all(DigitalTwin(df).replay())[0]


def stamp(path):
    s = Path(path).stat()
    return (s.st_size, s.st_mtime)


with st.sidebar:
    st.header("Traffic source")
    data_files = sorted(p.name for p in DATA_DIR.glob("*.csv")) if DATA_DIR.exists() else []
    source = st.radio("Use", ["CSV in the data/ folder", "Upload a CSV", "Demo data"],
                      index=0 if data_files else 2)
    label_col = st.text_input("Label column name (blank = auto-detect)", value="label")
    attack_values = st.text_input("Attack label values (comma-separated, optional)", value="")
    max_rows = st.number_input("Rows to read (0 = whole file)", min_value=0, value=200_000, step=50_000,
                               help="Real CIC-IoT-2023 files are large. A sample keeps the dashboard fast.")
    weight = st.slider("Security importance weight", 0.0, 1.0, 0.5, 0.05)

opts = (label_col.strip() or None, attack_values.strip() or None, int(max_rows) or None)

try:
    if source == "CSV in the data/ folder":
        if not data_files:
            st.warning("No CSV files in the data/ folder yet. Put Merged01.csv there, then refresh.")
            st.stop()
        name = st.sidebar.selectbox("File", data_files)
        path = str(DATA_DIR / name)
        df = load_cached(path, *opts, stamp(path))
    elif source == "Upload a CSV":
        uploaded = st.sidebar.file_uploader("Traffic CSV (up to 2 GB)", type=["csv"])
        if not uploaded:
            st.info("Choose a CSV file in the sidebar.")
            st.stop()
        UPLOAD_PATH.parent.mkdir(exist_ok=True)
        UPLOAD_PATH.write_bytes(uploaded.getvalue())
        df = load_cached(str(UPLOAD_PATH), *opts, (uploaded.name, uploaded.size))
    else:
        st.info("Using synthetic demonstration traffic.")
        df = load_cached(None, None, None, None, None)
except ValueError as e:
    st.error(str(e))
    st.stop()

snap = DigitalTwin(df).snapshot()
metrics = evaluate_cached(df)
ranked = rank_policies(metrics, weight)

st.subheader("Traffic snapshot")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Devices", f"{snap['devices']:,}")
c2.metric("Flow records", f"{snap['flow_count']:,}")
c3.metric("Attack flows", f"{snap['attack_flow_count']:,}")
c4.metric("Benign flows", f"{snap['benign_flow_count']:,}")
if snap["devices"] <= 2:
    st.warning("This file has no device/IP columns, so all flows share one source. "
               "'block_source' therefore blocks everything; interpret it with care.")

st.subheader("Recommended policy under selected weight")
st.success(f"{ranked.iloc[0]['policy']} — combined score {ranked.iloc[0]['combined_score']:.3f}")
st.dataframe(ranked)

st.subheader("Policy comparison")
st.dataframe(metrics)
st.bar_chart(metrics.set_index("policy")[["attack_reduction_pct"]])
st.bar_chart(metrics.set_index("policy")[[
    "benign_latency_ms_simulated", "benign_packet_loss_pct_simulated", "legitimate_traffic_disruption_pct"]])
st.download_button("Download metrics CSV", metrics.to_csv(index=False), "policy_metrics.csv", "text/csv")

"""Load IoT traffic (synthetic demo data or a CSV) into one standard format."""
import numpy as np
import pandas as pd

# Common column names in public flow datasets, mapped to the names this project uses.
ALIASES = {
    "timestamp": ["timestamp", "time", "flow_start", "stime", "ts"],
    "src_device": ["src_device", "src_ip", "source", "source_ip", "src"],
    "dst_device": ["dst_device", "dst_ip", "destination", "destination_ip", "dst"],
    "duration_s": ["duration_s", "flow_duration", "duration"],
    "packets": ["packets", "total_fwd_packets", "tot_pkts", "packet_count", "number"],
    "bytes": ["bytes", "totlen_fwd_pkts", "flow_bytes", "total_bytes", "tot sum"],
    "label": ["label", "class", "attack", "category", "is_attack"],
}

BENIGN_WORDS = {"benign", "normal", "0", "normal traffic", "benigntraffic"}


def demo_data(n=6000, seed=42):
    """Synthetic traffic for checking the code runs. NOT a research dataset."""
    rng = np.random.default_rng(seed)
    y = rng.choice([0, 1], n, p=[0.80, 0.20])
    duration = rng.lognormal(1.2, 0.5, n)
    packets = rng.poisson(np.where(y == 1, 160, 30)) + 1
    return pd.DataFrame({
        "timestamp": np.arange(n, dtype=float),
        "src_device": [f"device_{v}" for v in rng.integers(1, 61, n)],
        "dst_device": [f"device_{v}" for v in rng.integers(61, 91, n)],
        "duration_s": duration,
        "packets": packets,
        "bytes": packets * rng.integers(64, 900, n),
        "is_attack": y,
    })


def _rename_aliases(df):
    lower = {str(c).lower().strip(): c for c in df.columns}
    rename = {}
    for target, aliases in ALIASES.items():
        if target in df.columns:
            continue
        for a in aliases:
            if a in lower and lower[a] not in rename:
                rename[lower[a]] = target
                break
    return df.rename(columns=rename)


def _finalise(df):
    """Fill optional columns, force numeric columns to float, add flow ids."""
    defaults = {
        "timestamp": np.arange(len(df), dtype=float),
        "src_device": "unknown_src",
        "dst_device": "unknown_dst",
        "duration_s": 1.0,
        "packets": 1.0,
        "bytes": 0.0,
    }
    for col, val in defaults.items():
        if col not in df.columns:
            df[col] = val
    # Float (not int) so policies can scale traffic, e.g. x 0.30, on every pandas version.
    for col in ["timestamp", "duration_s", "packets", "bytes"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(float)
    df["duration_s"] = df["duration_s"].clip(lower=0.001)
    df["src_device"] = df["src_device"].astype(str)
    df["dst_device"] = df["dst_device"].astype(str)
    df["is_attack"] = df["is_attack"].astype(int)
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    df["flow_id"] = np.arange(len(df))
    return df


def load_dataset(csv_path=None, label_column=None, attack_values=None):
    """Return traffic with columns: timestamp, src_device, dst_device,
    duration_s, packets, bytes, is_attack (0 = benign, 1 = attack), flow_id."""
    if not csv_path:
        return _finalise(demo_data())

    df = pd.read_csv(csv_path, low_memory=False)
    if label_column:
        if label_column not in df.columns:
            raise ValueError(f"Label column '{label_column}' not found. Columns: {list(df.columns)}")
        df = df.rename(columns={label_column: "label"})
    df = _rename_aliases(df)
    if "label" not in df.columns:
        raise ValueError("Could not find the label column. Use --label-column with the exact CSV column name.")

    labels = df["label"].astype(str).str.strip().str.lower()
    if attack_values:
        vals = {v.strip().lower() for v in attack_values.split(",")}
        df["is_attack"] = labels.isin(vals).astype(int)
    else:
        numeric = pd.to_numeric(df["label"], errors="coerce")
        if numeric.notna().all() and set(numeric.unique()).issubset({0, 1}):
            df["is_attack"] = numeric.astype(int)
        else:
            df["is_attack"] = (~labels.isin(BENIGN_WORDS)).astype(int)
    return _finalise(df)

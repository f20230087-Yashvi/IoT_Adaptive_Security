"""Measure each policy and rank them (security benefit vs. operational cost)."""
import pandas as pd

from .policies import POLICIES, execute_policy

# Illustrative action-execution delays, NOT measurements from a real controller.
RESPONSE_TIME_MS = {
    "no_mitigation": 0.0,
    "block_source": 35.0,
    "isolate_attacker": 50.0,
    "rate_limit": 25.0,
    "reroute": 80.0,
}

COST_COLUMNS = [
    "response_time_ms_simulated",
    "benign_latency_ms_simulated",
    "benign_packet_loss_pct_simulated",
    "legitimate_traffic_disruption_pct",
]


def evaluate_one(traffic, policy):
    x = execute_policy(traffic, policy)
    a = x["is_attack"].eq(1)
    b = ~a
    # "Before" always uses the ORIGINAL traffic, so rate limiting's reduction is counted.
    original_bytes = traffic["bytes"].astype(float).to_numpy()
    attack_before = float(original_bytes[a.to_numpy()].sum())
    attack_after = float(x.loc[a, "delivered_bytes"].sum())
    benign_before = float(original_bytes[b.to_numpy()].sum())
    benign_after = float(x.loc[b, "delivered_bytes"].sum())
    total_duration = max(float(x["duration_s"].sum()), 1.0)
    row = {
        "policy": policy,
        "attack_reduction_pct": 100 * (1 - attack_after / max(attack_before, 1)),
        "response_time_ms_simulated": RESPONSE_TIME_MS[policy],
        "throughput_mbps_simulated": float(x["delivered_bytes"].sum()) * 8 / total_duration / 1e6,
        "benign_latency_ms_simulated": float(x.loc[b, "extra_delay_ms"].mean()) if b.any() else 0.0,
        "benign_packet_loss_pct_simulated": 100 * float(x.loc[b, "packet_loss_fraction"].mean()) if b.any() else 0.0,
        "legitimate_traffic_disruption_pct": 100 * (1 - benign_after / max(benign_before, 1)),
    }
    return row, x


def evaluate_all(traffic):
    rows, details = [], {}
    for p in POLICIES:
        row, flows = evaluate_one(traffic, p)
        rows.append(row)
        details[p] = flows
    return pd.DataFrame(rows), details


def _minmax(s):
    rng = s.max() - s.min()
    return (s - s.min()) / rng if rng > 0 else pd.Series(0.0, index=s.index)


def rank_policies(results, security_weight=0.5):
    """score = w * security_score + (1 - w) * operational_score.
    Each cost metric is min-max normalised separately, then averaged,
    so no single unit (ms vs %) dominates."""
    r = results.copy()
    security = _minmax(r["attack_reduction_pct"])
    cost = sum(_minmax(r[c]) for c in COST_COLUMNS) / len(COST_COLUMNS)
    operational = 1 - cost
    r["security_score_0_1"] = security
    r["operational_score_0_1"] = operational
    r["combined_score"] = security_weight * security + (1 - security_weight) * operational
    return r.sort_values("combined_score", ascending=False).reset_index(drop=True)

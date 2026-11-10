"""Run the full experiment: load traffic -> Digital Twin -> policies -> metrics -> ranking -> graphs."""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # save graphs to files; no pop-up window needed
import matplotlib.pyplot as plt

from iot_twin.data import load_dataset
from iot_twin.evaluate import evaluate_all, rank_policies
from iot_twin.twin import DigitalTwin


def main():
    ap = argparse.ArgumentParser(description="Digital Twin adaptive IoT mitigation evaluation")
    ap.add_argument("--csv", default=None, help="Path to a traffic CSV (omit to use demo data)")
    ap.add_argument("--label-column", default=None, help="Exact label column name in the CSV")
    ap.add_argument("--attack-values", default=None, help="Comma-separated attack label values")
    ap.add_argument("--security-weight", type=float, default=0.5, help="Security weight between 0 and 1")
    ap.add_argument("--out", default="outputs")
    args = ap.parse_args()
    if not 0 <= args.security_weight <= 1:
        ap.error("--security-weight must be between 0 and 1")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    traffic = load_dataset(args.csv, args.label_column, args.attack_values)
    twin = DigitalTwin(traffic)
    traffic.to_csv(out / "input_replay.csv", index=False)

    results, details = evaluate_all(twin.replay())
    ranked = rank_policies(results, args.security_weight)
    results.to_csv(out / "policy_metrics.csv", index=False)
    ranked.to_csv(out / "policy_ranking.csv", index=False)
    for policy, flows in details.items():
        flows.to_csv(out / f"flows_{policy}.csv", index=False)

    ax = results.plot(x="policy", y="attack_reduction_pct", kind="bar", legend=False, rot=25)
    ax.set_ylabel("Attack traffic reduction (%)")
    ax.set_title("Security effectiveness by policy")
    plt.tight_layout()
    plt.savefig(out / "attack_reduction.png", dpi=160)
    plt.close()

    cols = ["benign_latency_ms_simulated", "benign_packet_loss_pct_simulated", "legitimate_traffic_disruption_pct"]
    ax = results.set_index("policy")[cols].plot(kind="bar", rot=25)
    ax.set_title("Simulated operational impact")
    ax.set_ylabel("Value (units shown in legend)")
    plt.tight_layout()
    plt.savefig(out / "operational_impact.png", dpi=160)
    plt.close()

    print("\nDigital Twin snapshot:", twin.snapshot())
    print("\nPolicy metrics:\n", results.round(3).to_string(index=False))
    print("\nRanking:\n", ranked[["policy", "security_score_0_1", "operational_score_0_1", "combined_score"]]
          .round(3).to_string(index=False))
    print(f"\nRecommended policy: {ranked.iloc[0]['policy']}")
    print(f"\nOutputs saved to: {out.resolve()}")
    print("\nNOTE: demo data and QoS/response values are simulated proxies, not measured network results.")


if __name__ == "__main__":
    main()

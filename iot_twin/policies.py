"""The candidate mitigation strategies executed inside the Digital Twin."""
import numpy as np
import pandas as pd

POLICIES = ["no_mitigation", "block_source", "isolate_attacker", "rate_limit", "reroute"]


def execute_policy(traffic: pd.DataFrame, policy: str) -> pd.DataFrame:
    x = traffic.copy()
    # Make sure the traffic columns can hold decimals (fixes pandas LossySetitemError).
    x[["bytes", "packets"]] = x[["bytes", "packets"]].astype(float)

    attack = x["is_attack"].eq(1)
    benign = ~attack
    x["blocked"] = False
    x["extra_delay_ms"] = 2.0
    x["packet_loss_fraction"] = 0.0
    x["policy_note"] = "baseline"

    if policy == "no_mitigation":
        pass
    elif policy == "block_source":
        # Block ALL flows from any source seen sending an attack flow.
        bad_sources = set(x.loc[attack, "src_device"].astype(str))
        x["blocked"] = x["src_device"].astype(str).isin(bad_sources)
        x.loc[x["blocked"], "policy_note"] = "source blocked"
    elif policy == "isolate_attacker":
        # Flow-level approximation: block only the attack flows.
        x.loc[attack, "blocked"] = True
        x.loc[attack, "policy_note"] = "attack flow isolated"
    elif policy == "rate_limit":
        # Illustrative: attack load cut by 70%, benign load throttled by 5%.
        x.loc[attack, ["bytes", "packets"]] = x.loc[attack, ["bytes", "packets"]] * 0.30
        x.loc[benign, ["bytes", "packets"]] = x.loc[benign, ["bytes", "packets"]] * 0.95
        x.loc[attack, "policy_note"] = "attack traffic rate limited"
    elif policy == "reroute":
        # Proxy only: real rerouting needs Mininet / a real network.
        x.loc[attack, "extra_delay_ms"] = 18.0
        x.loc[benign, "extra_delay_ms"] = 8.0
        x["packet_loss_fraction"] = 0.02
        x["policy_note"] = "rerouted (simulated)"
    else:
        raise ValueError(f"Unknown policy: {policy}")

    blocked = x["blocked"].astype(bool)
    x["blocked"] = blocked
    x["delivered_bytes"] = np.where(blocked, 0.0, x["bytes"])
    x["delivered_packets"] = np.where(blocked, 0.0, x["packets"])
    x.loc[blocked, "packet_loss_fraction"] = 1.0
    x.loc[blocked, "extra_delay_ms"] = 0.0
    return x

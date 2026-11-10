"""A lightweight, flow-level Digital Twin of the IoT network."""
import pandas as pd


class DigitalTwin:
    """Holds a virtual copy of the network's devices and traffic so every
    mitigation policy can be tested on exactly the same scenario."""

    def __init__(self, traffic: pd.DataFrame):
        self.original = traffic.copy()
        devices = set(traffic["src_device"].astype(str)) | set(traffic["dst_device"].astype(str))
        self.state = {
            "devices": len(devices),
            "flow_count": int(len(traffic)),
            "attack_flow_count": int(traffic["is_attack"].sum()),
            "benign_flow_count": int((traffic["is_attack"] == 0).sum()),
        }

    def replay(self) -> pd.DataFrame:
        """Return a fresh, timestamp-ordered copy of the scenario."""
        return self.original.sort_values("timestamp", kind="stable").copy()

    def snapshot(self) -> dict:
        return dict(self.state)

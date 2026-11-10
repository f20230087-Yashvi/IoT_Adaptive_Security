# Digital Twin-Based Adaptive Security Evaluation for IoT Networks

A flow-level software prototype for the project abstract. It replays an IoT traffic scenario inside a Digital Twin, runs
several mitigation strategies against the same scenario, measures security and service impact, and ranks the strategies.

## Project files
| File | What it does |
|---|---|
| `iot_twin/data.py` | Loads synthetic demo traffic or your CSV and maps the labels to `is_attack` (0/1) |
| `iot_twin/twin.py` | The Digital Twin: a virtual copy of the devices and traffic that can be replayed |
| `iot_twin/policies.py` | The 5 strategies: no mitigation, block source, isolate attacker, rate limit, reroute |
| `iot_twin/evaluate.py` | Calculates the metrics and ranks the policies with a weighted score |
| `run_project.py` | Runs the whole experiment and saves CSVs and graphs to `outputs/` |
| `dashboard.py` | An interactive web dashboard (Streamlit) |

## Setup (one time)
Use Python 3.10 or newer. Open a terminal in this folder and run:
```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```bash
python run_project.py              # demo data
streamlit run dashboard.py         # dashboard in your browser
```
Results are saved in `outputs/`: `policy_metrics.csv`, `policy_ranking.csv`, `attack_reduction.png`,
`operational_impact.png` and a `flows_<policy>.csv` file for each policy.

## Using a real dataset (for example CIC-IoT-2023)
Put the CSV in `data/`, then run:
```bash
python run_project.py --csv data/your_file.csv --label-column label
python run_project.py --csv data/your_file.csv --label-column label --attack-values "DDoS-SYN_Flood,Mirai-udpplain"
```
Without `--attack-values`, every label except benign/normal counts as an attack. Common column names (src_ip,
flow_duration, label and so on) are detected automatically. Check your dataset's real columns and adjust `ALIASES`
in `iot_twin/data.py` if you need to.

`--security-weight` (0 to 1, default 0.5) sets how much security counts compared with service impact.

## Metrics
- **Attack reduction (%)** = 100 × (1 − delivered attack bytes / original attack bytes)
- **Legitimate traffic disruption (%)** = 100 × (1 − delivered benign bytes / original benign bytes)
- **Throughput (proxy)** = delivered bytes × 8 / total flow duration
- **Response time, benign latency and packet loss** are fixed, illustrative *simulated* values

## Ranking
Each cost metric (response time, latency, packet loss and disruption) is min-max normalised and then averaged. The
attack reduction is also normalised.
`combined_score = w × security_score + (1 − w) × operational_score`

## Limitations (state these in your report)
1. The demo data is synthetic and only shows that the code runs. It is not a research dataset.
2. This is a flow-level software twin, not one synchronised with a live physical network.
3. Latency, packet loss and response time are modelled, not measured. Do not present them as real measurements.
4. Rerouting and isolation are approximations. Use Mininet or a testbed for packet-level validation.
5. The dataset's own labels stand in for the IDS output. For a full pipeline, train a detector (for example a Random
   Forest) and pass its predictions to the twin.

# SAT-SA Composite Risk Scoring Methodology (v2)

The SAT-SA Supervisory Risk Scoring Engine computes an explainable, bounded **Composite Risk Score (0–100)** for each Cyber Security Entity (CSE). The score enables national cybersecurity authorities (NCIIPC, NTRO, CERT-In) to prioritize intervention, audit readiness, and incident response across critical infrastructure sectors.

---

## 1. Mathematical Formulation

$$\text{Composite Risk Score} = \min\left(100.0, \; S_{\text{rules}} + S_{\text{anomalies}} + S_{\text{peers}} + S_{\text{silent}} + S_{\text{CTI}} + S_{\text{traceback}}\right)$$

Where each component reflects a distinct operational dimension:

| Component | Dimension | Max Contribution | Description |
|---|---|---|---|
| $S_{\text{rules}}$ | Declarative Rule Violations | **25 pts** | Unescalated critical alerts, uninvestigated closed cases, missing SOP triage steps |
| $S_{\text{anomalies}}$ | Temporal & Behavioral Anomalies | **20 pts** | Z-score alert volume spikes/drops ($Z \ge 3.0$), Isolation Forest multivariate deviations |
| $S_{\text{peers}}$ | Peer Benchmark Deviations | **15 pts** | Gamed/ultra-rapid MTTR, 0% escalation rate vs sector cohort medians |
| $S_{\text{silent}}$ | Negative Space Blind Spots | **15 pts** | Unmonitored critical assets reporting 0 alerts over 30 days, category blind spots |
| $S_{\text{CTI}}$ | Threat Intelligence Matches | **25 pts** | Correlation of observed alert IPs/domains against verified offline CTI feeds |
| $S_{\text{traceback}}$ | AI Attack Traceback & Multi-Stage Progression | **30 pts** | Corroborated multi-stage MITRE kill chain with lateral movement and high confidence |

---

## 2. Component Calculations

### 2.1 Rule Violations ($S_{\text{rules}}$, max 25)
Calculated from the editable rules in `backend/rules/*.yaml`:
$$S_{\text{rules}} = \min\left(25.0, \; 10.0 \cdot N_{\text{crit}} + 5.0 \cdot N_{\text{high}} + 2.5 \cdot N_{\text{med}} + 1.0 \cdot N_{\text{low}}\right)$$

### 2.2 Anomalies ($S_{\text{anomalies}}$, max 20)
Calculated from statistical Z-score spikes and Isolation Forest multivariate anomalies:
$$S_{\text{anomalies}} = \min\left(20.0, \; 12.0 \cdot A_{\text{crit}} + 7.0 \cdot A_{\text{high}} + 3.0 \cdot A_{\text{med}}\right)$$

### 2.3 Peer Benchmark Deviations ($S_{\text{peers}}$, max 15)
Calculated by benchmarking against sector and cohort medians:
- **Rapid Closure / Metric Gaming**: Critical MTTR $< 120$s while cohort median $> 600$s ($+10$ pts).
- **Under-Escalation**: Escalation rate $< 2\%$ while cohort median $> 10\%$ ($+10$ pts).
- **Investigation Coverage Gap**: $< 35\%$ coverage while cohort median $> 60\%$ ($+8$ pts).

### 2.4 Negative Space ($S_{\text{silent}}$, max 15)
- **Silent Critical Asset**: $15$ pts per high-criticality asset with zero alerts across 30 days.
- **Category Blind Spot**: $5$ pts per threat category where peers average $\ge 5$ alerts and CSE has $0$.

### 2.5 Threat Intelligence ($S_{\text{CTI}}$, max 25)
Evaluates intersections between observed telemetry (source/dest IPs) and local CTI Knowledge Base:
$$S_{\text{CTI}} = \begin{cases} 0 & \text{if no IOC matches} \\ \min\left(25.0, \; 15.0 + \sum_{i \in \text{matches}} (\text{confidence}_i \cdot 10.0)\right) & \text{if IOC matches exist} \end{cases}$$

### 2.6 AI Attack Traceback ($S_{\text{traceback}}$, max 30)
Evaluates multi-stage attack reconstruction confidence:
$$S_{\text{traceback}} = \min\left(30.0, \; \frac{\text{Confidence}}{100} \cdot 20.0 + \text{Bonus}_{\text{stages}}\right)$$
Where $\text{Bonus}_{\text{stages}} = 10.0$ if the reconstructed attack exhibits $\ge 4$ verified stages (Initial Access, Privilege Escalation, Lateral Movement, Data Access, Evidence Tampering).

---

## 3. Supervisory Risk Tiers

| Score Range | Risk Level | Supervisory Action Required |
|---|---|---|
| **76 – 100** | **CRITICAL** | Urgent intervention: confirmed adversary presence or systemic blind spots. Incident response escalation. |
| **51 – 75** | **HIGH** | Formal supervisory audit: unescalated critical incidents, gaming indicators, or significant telemetry drops. |
| **26 – 50** | **MODERATE** | Elevated monitoring: minor compliance or peer benchmark deviations. |
| **0 – 25** | **LOW** | Routine surveillance: healthy SOC operations within normative tolerances. |

---

## 4. Explainability & Auditability

Every risk score calculation provides a machine-readable and human-readable breakdown containing:
1. Exact component scores and finding counts.
2. Matched threat actor, malware family, and CTI indicators.
3. Top contributing findings with direct evidence IDs.
4. Prescriptive supervisory recommendations for regulatory action.

# Network Threat Analytics Platform

**End-to-end data analytics project** — Python data engineering → PostgreSQL analysis → Power BI dashboard, built on a 40,000-event network security dataset.

---

## Business Problem

A security operations team needs visibility into how network threats are detected, classified, and responded to — specifically whether high-severity incidents receive an appropriately strong response, and whether monitoring coverage actually influences that response. This project simulates that analysis end-to-end, from raw log data to an executive-ready dashboard.

---

## Tech Stack

| Layer | Tool |
|---|---|
| Data cleaning & feature engineering | Python (pandas, numpy) |
| Analytical querying | PostgreSQL (window functions, CTEs, conditional aggregation) |
| Visualization & reporting | Power BI |

---

## 1. Data Preparation (Python)

Starting from a raw 40,000-row CSV (`cybersecurity_attacks.csv`) with 25 columns, the following features were engineered:

- **Null-flag standardization** — converted ambiguous nulls in `Malware Indicators`, `Alerts/Warnings`, `Firewall Logs`, and `IDS/IPS Alerts` into explicit Yes/No signals; added a separate `proxy_used` flag while preserving the original `Proxy Information` IP data.
- **Timestamp decomposition** — parsed the raw string timestamp into `date`, `hour`, `day_of_week`, and `year_month` fields for time-based analysis.
- **Port categorization** — classified `Source Port`/`Destination Port` into Well-known (0–1023) vs. Registered/Dynamic (1024–65535) using `np.where()`.
- **Detection Coverage Score** — engineered a 0–4 composite score counting how many of the four detection signals fired per event, enabling analysis of monitoring thoroughness.
- **Response Alignment flag** — flagged High-severity events that were *not* Blocked, isolating "under-responded" incidents for direct investigation.
- **Geo-location split** — parsed combined location strings into separate `city` and `state_region` fields.

---

## 2. Analytical Queries (SQL)

Loaded the cleaned dataset into PostgreSQL and answered seven core business questions, including:

- Monthly/yearly trend in total vs. high-severity events
- Most frequent attack type per network segment, and whether that varies by protocol (using `RANK() OVER (PARTITION BY ...)`)
- Proportion of high-severity events Blocked vs. Logged vs. Ignored, broken out by network segment to locate the largest response gaps
- Correlation between Detection Coverage Score and Action Taken
- Ranking of attack signatures by frequency within each attack type using window functions

---

## 3. Dashboard (Power BI)

A 3-page interactive report:

1. **Dashboard Overview** — KPI cards (Total Events, % High Severity, % Blocked, Avg. Anomaly Score), monthly event volume trend by severity, and attack type frequency by segment/protocol. Fully slicer-driven (Attack Type, Severity Level, Network Segment, Protocol, Date).
2. **Event Details** — Action Taken vs. Severity breakdown exposing response gaps, anomaly score distribution histogram, and a drill-through table of individual event records.
3. **Summary & Recommendations** — Narrative page with top findings and recommended actions for stakeholders.

---

## Key Findings

| Finding | Business Implication |
|---|---|
| **~22% of High-severity events were not blocked** (Logged/Ignored instead) | Real response-alignment gap; recommend enforced auto-blocking for High-severity classifications |
| **Detection Coverage Score shows no correlation with Action Taken** (avg. ≈2.0/4 across all response types) | Response decisions don't currently factor in how well an event was monitored — a triage design gap |
| **Anomaly scores are uniformly distributed (0–100)**, unlike the low-skewed pattern expected in real traffic | Dataset shows signs of synthetic generation; scores should be treated as directional only |
| **100% of traffic uses Registered/Dynamic ports** — zero events touch well-known service ports (80, 443, 22) | Further evidence of synthetic data; recommend validating any port-based rule against real traffic before production use |

**Overall takeaway:** the data reveals a *response-alignment* problem more than a *detection* problem — monitoring signals are present, but they aren't consistently driving proportional action. This is the single highest-leverage fix identified.

---

## Data Limitations

This dataset is partially synthetic. Several patterns (uniform anomaly scores, exclusively high-numbered ports, zero correlation between monitoring and response) are more consistent with randomly generated fields than real production traffic. Findings and recommendations here demonstrate the analytical *process* and should be re-validated against live data before any operational use.

---

## What I'd Do With More Time / Real Data

- Correlation matrix across all engineered numeric features
- Hour-of-day × day-of-week heatmap for attack timing patterns
- Geo-mapped visualization of event/severity concentration
- Automated data quality checks as a reusable Python module for future ingests

---

*Built as an end-to-end portfolio project covering the full analytics lifecycle: raw data → cleaning → SQL analysis → BI storytelling.*

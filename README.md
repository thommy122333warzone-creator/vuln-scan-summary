# Vulnerability Scan Summary

A small Python tool that reads a vulnerability scan export (CSV) and summarises the open findings by severity, highlights the assets with the most issues, and lists findings that are overdue for remediation.

I built this as part of my professional learning plan (UTS 43030), following YouTube tutorials from freeCodeCamp and Corey Schafer, to practise Python for security tasks.

## What it does

- Converts each finding's CVSS v3 score into a severity rating (Critical, High, Medium, Low)
- Counts open findings by severity
- Shows the top 5 assets with the most open findings
- Flags findings that are older than an example remediation timeframe:

| Severity | Remediate within |
|----------|------------------|
| Critical | 14 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |

- Optionally saves the summary to a JSON file

## Requirements

Python 3.8 or later. No extra packages are needed (standard library only).

## How to run

```bash
python vuln_summary.py sample_data/sample_scan.csv
```

Use a fixed report date (so the results are repeatable):

```bash
python vuln_summary.py sample_data/sample_scan.csv --date 2026-11-15
```

Save the summary as JSON:

```bash
python vuln_summary.py sample_data/sample_scan.csv --json summary.json
```

## CSV format

The CSV needs these columns:

| Column | Example |
|--------|---------|
| asset | web-srv-01 |
| ip_address | 10.0.1.10 |
| vulnerability | SMBv1 enabled |
| cve | CVE-2021-44228 (can be blank) |
| cvss_score | 7.5 |
| first_found | 2026-08-05 (YYYY-MM-DD) |
| status | Open / Remediated |

## KQL practice

The `kql/` folder has a query I wrote while following KQL tutorials. It runs in Microsoft's free [Log Analytics demo environment](https://aka.ms/LADemo).

## Note on data

`sample_data/sample_scan.csv` is **made-up sample data** created for this project. No real organisation's data is used.

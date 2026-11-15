"""
vuln_summary.py - Summarise a vulnerability scan export (CSV).

Reads a CSV of scan findings and prints a summary of open findings:
  * count by severity (based on the CVSS v3 rating scale)
  * the assets with the most open findings
  * findings that are overdue for remediation
It can also save the summary to a JSON file.

Usage:
    python vuln_summary.py sample_data/sample_scan.csv
    python vuln_summary.py sample_data/sample_scan.csv --json summary.json
    python vuln_summary.py sample_data/sample_scan.csv --date 2026-11-15

Only uses the Python standard library. Use sample or anonymised data only.
"""

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import date

# CVSS v3.x qualitative severity rating scale
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]

# Example remediation timeframes (days) for each severity
REMEDIATION_DAYS = {"Critical": 14, "High": 30, "Medium": 90, "Low": 180, "None": 365}

REQUIRED_COLUMNS = {"asset", "vulnerability", "cvss_score", "first_found", "status"}


def cvss_to_severity(score):
    """Convert a CVSS v3 base score into a severity rating."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def load_findings(path):
    """Read the CSV file and return a list of finding dictionaries."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"Error: CSV is missing columns: {', '.join(sorted(missing))}")

        findings = []
        for line_no, row in enumerate(reader, start=2):
            try:
                score = float(row["cvss_score"])
                found = date.fromisoformat(row["first_found"])
            except ValueError:
                print(f"Warning: skipping line {line_no} (bad score or date)", file=sys.stderr)
                continue
            row["cvss_score"] = score
            row["first_found"] = found
            row["severity"] = cvss_to_severity(score)
            findings.append(row)
    return findings


def summarise(findings, today):
    """Build a summary of the open findings."""
    open_findings = [f for f in findings if f["status"].strip().lower() == "open"]

    by_severity = Counter(f["severity"] for f in open_findings)
    by_asset = Counter(f["asset"] for f in open_findings)

    overdue = []
    for f in open_findings:
        age = (today - f["first_found"]).days
        if age > REMEDIATION_DAYS[f["severity"]]:
            overdue.append({
                "asset": f["asset"],
                "vulnerability": f["vulnerability"],
                "cve": f.get("cve", ""),
                "severity": f["severity"],
                "age_days": age,
            })
    overdue.sort(key=lambda x: (SEVERITY_ORDER.index(x["severity"]), -x["age_days"]))

    return {
        "report_date": today.isoformat(),
        "total_findings": len(findings),
        "open_findings": len(open_findings),
        "remediated_findings": len(findings) - len(open_findings),
        "open_by_severity": {s: by_severity.get(s, 0) for s in SEVERITY_ORDER},
        "top_assets": by_asset.most_common(5),
        "overdue": overdue,
    }


def print_summary(summary):
    """Print the summary as a readable report in the terminal."""
    print("=" * 60)
    print(f" VULNERABILITY SCAN SUMMARY  (as at {summary['report_date']})")
    print("=" * 60)
    print(f"Total findings:      {summary['total_findings']}")
    print(f"Open findings:       {summary['open_findings']}")
    print(f"Remediated findings: {summary['remediated_findings']}")

    print("\nOpen findings by severity")
    print("-" * 30)
    for severity, count in summary["open_by_severity"].items():
        if severity == "None":
            continue
        print(f"  {severity:<10} {count:>3}  {'#' * count}")

    print("\nAssets with the most open findings")
    print("-" * 30)
    for asset, count in summary["top_assets"]:
        print(f"  {asset:<18} {count:>3}")

    print(f"\nOverdue findings ({len(summary['overdue'])})")
    print("-" * 30)
    for item in summary["overdue"]:
        cve = f" [{item['cve']}]" if item["cve"] else ""
        print(f"  {item['severity']:<8} {item['age_days']:>4} days  {item['asset']}: {item['vulnerability']}{cve}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Summarise a vulnerability scan CSV export.")
    parser.add_argument("csv_file", help="Path to the scan export CSV")
    parser.add_argument("--json", metavar="FILE", help="Also save the summary to a JSON file")
    parser.add_argument("--date", metavar="YYYY-MM-DD", help="Report date (default: today)")
    args = parser.parse_args()

    today = date.fromisoformat(args.date) if args.date else date.today()
    findings = load_findings(args.csv_file)
    summary = summarise(findings, today)
    print_summary(summary)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"Summary saved to {args.json}")


if __name__ == "__main__":
    main()

# When Severity Does Not Equal Risk

### A Longitudinal Analysis of Vulnerability Severity and Real-World Exploitation

This repository contains my Master's Research Capstone project for DATA 698 in the CUNY School of Professional Studies M.S. in Data Science program.

## Project Overview

Organizations commonly use the Common Vulnerability Scoring System (CVSS) to help prioritize software vulnerabilities for remediation. CVSS measures the technical severity of a vulnerability on a scale from 0 to 10, but technical severity does not necessarily reflect whether a vulnerability is being exploited in the real world.

This project examines the relationship between CVSS severity and known real-world exploitation from 2020–2026. The goal is to identify situations where severity-based prioritization may under-prioritize vulnerabilities that are known to be exploited and to explore the characteristics associated with these mismatches.

## Research Question

**How often does severity-based vulnerability prioritization under-prioritize vulnerabilities known to be exploited, what characteristics are associated with these mismatches, and have these patterns changed over time?**

The analysis also explores:

- How results change under different CVSS prioritization thresholds
- Whether mismatch patterns differ by vulnerability characteristics such as CWE and attack characteristics
- How CVSS severity compares with EPSS exploitation probability
- Whether the relationship between severity and known exploitation has changed over time

## Data Sources

The project combines three public cybersecurity data sources:

### National Vulnerability Database (NVD)

NVD vulnerability records from 2020–2026 provide CVE identifiers, CVSS scores, CVSS metrics, CWE classifications, publication dates, and other vulnerability characteristics.

### CISA Known Exploited Vulnerabilities (KEV) Catalog

The KEV catalog identifies vulnerabilities that have evidence of exploitation in the wild. CVEs appearing in KEV are treated as vulnerabilities with documented real-world exploitation.

Absence from KEV is **not** interpreted as proof that a vulnerability has never been exploited.

### Exploit Prediction Scoring System (EPSS)

EPSS provides an estimate of the probability that a vulnerability will be exploited. A current EPSS snapshot is used as an additional comparison with CVSS severity and KEV status.

## Repository Structure

```text
data698-capstone/
├── data/
│   ├── raw/              # Original NVD, KEV, and EPSS data
│   └── processed/        # Cleaned and merged analysis datasets
│
├── notebooks/
│   └── feasibility_eda.ipynb
│
├── figures/              # Figures generated during analysis
├── results/              # Statistical and modeling outputs
├── docs/                 # Capstone papers and presentation materials
├── .gitignore
└── README.md

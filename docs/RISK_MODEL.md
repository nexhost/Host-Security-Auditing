# HSA Risk Model

HSA risk is separate from CVSS. Inputs are normalized to 0–1 and combined as:

```text
100 × (0.20 criticality + 0.20 exposure + 0.25 severity +
       0.10 confidence + 0.15 vulnerability evidence + 0.10 service sensitivity)
```

Levels are Critical ≥85, High ≥65, Medium ≥40, Low ≥15, and Informational below 15. Open ports influence exposure but never prove exploitability. The offline default CVE provider contributes no vulnerability score; provider-backed matches remain “Potential CVE match” until validated.

# Detection gap run report

Model backend: offline-heuristic

## Coverage of malicious events (share detected)

| Technique | Dev before | Dev after | Holdout before | Holdout after |
|---|---|---|---|---|
| T1003.001 | 33% | 100% | 33% | 100% |
| T1053.005 | 0% | 100% | 0% | 100% |
| T1059.001 | 100% | 100% | 100% | 100% |
| T1070.001 | 0% | 100% | 0% | 100% |
| T1218.011 | 0% | 100% | 0% | 100% |

## New rules

| Technique | Status | Fix rounds | Dev P / R | Holdout P / R | Holdout FP |
|---|---|---|---|---|---|
| T1003.001 | accepted | 2 | 1.0 / 1.0 | 0.6 / 1.0 | 2 |
| T1070.001 | accepted | 2 | 1.0 / 1.0 | 0.667 / 1.0 | 1 |
| T1053.005 | accepted | 1 | 1.0 / 1.0 | 0.667 / 1.0 | 1 |
| T1218.011 | accepted | 1 | 1.0 / 1.0 | 0.667 / 1.0 | 1 |

Benign holdout events alerted on by the new rules: 5

## Holdout errors (what the dev data did not teach the rule)

- false positive for T1003.001: `tasklist /svc | findstr lsass`
- false positive for T1003.001: `wmic process where name="lsass.exe" get processid`
- false positive for T1070.001: `wevtutil epl Security C:\Backup\sec.evtx`
- false positive for T1053.005: `schtasks /create /tn "PatchTuesday" /tr "C:\Program Files\Patch\p.exe" /sc weekly`
- false positive for T1218.011: `rundll32.exe url.dll,FileProtocolHandler https://example.com`

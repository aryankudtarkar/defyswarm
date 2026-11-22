# DefySwarm Evaluation Lab — Scorecard

> Every number below comes from the stored run named in the footer. Detectors replay label-stripped events; ground truth is used only for scoring. Baselines are reference implementations, not vendor products.

## Headline

- **D9 DefySwarm overall detection:** 100.0% [96.7%, 100.0%] across 112 attack traces; FP trace rate 0.0% [0.0%, 2.3%] across 162 traces.
- **D9 median time to detect:** 0 ms (p95 0 ms); median files lost 1, worst 1.
- **Containment latency used for the primary table:** 48 ms (live simulator MTTC median (8 runs)).

## Benign workload

| Family | Detector | Traces | Detection rate (95% CI) | FP trace rate (95% CI) | Median TTD | p95 TTD | Median files lost | Worst files lost | Recoverable | McNemar p vs D9 | Median files-lost diff vs D9 [95% CI] |
| :--- | :--- | ---: | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| benign | D0 No protection (versioning or nothing) | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D1 Snapshot / backup only | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D2 Per-principal behavioural anomaly | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D3 Per-principal batch rate rule | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D4 Malware / signature scan on upload | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D5 Sync-client ransomware heuristic | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D6 Extension and ransom-note blacklist | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D7 Naive fixed-name canary | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D8 Entropy-only threshold | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D9 DefySwarm full | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D9a DefySwarm minus canaries | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D9b DefySwarm minus sabotage triggers | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D9c DefySwarm minus entropy/magic | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D9d DefySwarm minus swarm correlation | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D9e DefySwarm minus honey credentials | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |
| benign | D9f DefySwarm minus vault | 50 | n/a n/a | 0.0% [0.0%, 7.1%] | — | — | 0 | 0 | 100.0% | 1.000 | — |

For benign traces the detection-rate column is not applicable; the FP trace rate is the alert rate on workloads that contain no attack.

## Ransomware

| Family | Detector | Traces | Detection rate (95% CI) | FP trace rate (95% CI) | Median TTD | p95 TTD | Median files lost | Worst files lost | Recoverable | McNemar p vs D9 | Median files-lost diff vs D9 [95% CI] |
| :--- | :--- | ---: | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| ransomware | D0 No protection (versioning or nothing) | 46 | 0.0% [0.0%, 7.7%] | 0.0% [0.0%, 7.7%] | — | — | 18 | 24 | 82.6% | <0.001 | +17.0 [+12.0, +18.0] |
| ransomware | D1 Snapshot / backup only | 46 | 0.0% [0.0%, 7.7%] | 0.0% [0.0%, 7.7%] | — | — | 18 | 24 | 100.0% | <0.001 | +17.0 [+12.0, +18.0] |
| ransomware | D2 Per-principal behavioural anomaly | 46 | 15.2% [7.6%, 28.2%] | 0.0% [0.0%, 7.7%] | 12500 ms | 48000 ms | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +18.0] |
| ransomware | D3 Per-principal batch rate rule | 46 | 67.4% [53.0%, 79.1%] | 0.0% [0.0%, 7.7%] | 57850 ms | 59050 ms | 18 | 24 | 0.0% | <0.001 | +17.0 [+12.0, +18.0] |
| ransomware | D4 Malware / signature scan on upload | 46 | 60.9% [46.5%, 73.6%] | 0.0% [0.0%, 7.7%] | 25 ms | 525 ms | 1 | 24 | 0.0% | <0.001 | 0.0 [0.0, +11.0] |
| ransomware | D5 Sync-client ransomware heuristic | 46 | 13.0% [6.1%, 25.7%] | 0.0% [0.0%, 7.7%] | 500 ms | 525 ms | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +18.0] |
| ransomware | D6 Extension and ransom-note blacklist | 46 | 17.4% [9.1%, 30.7%] | 0.0% [0.0%, 7.7%] | 0 ms | 500 ms | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +18.0] |
| ransomware | D7 Naive fixed-name canary | 46 | 30.4% [19.1%, 44.8%] | 0.0% [0.0%, 7.7%] | 150 ms | 300 ms | 12 | 24 | 0.0% | <0.001 | +11.0 [+11.0, +17.0] |
| ransomware | D8 Entropy-only threshold | 46 | 60.9% [46.5%, 73.6%] | 0.0% [0.0%, 7.7%] | 525 ms | 24525 ms | 4 | 24 | 0.0% | <0.001 | +3.0 [+1.0, +11.0] |
| ransomware | D9 DefySwarm full | 46 | 100.0% [92.3%, 100.0%] | 0.0% [0.0%, 7.7%] | 0 ms | 25 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| ransomware | D9a DefySwarm minus canaries | 46 | 100.0% [92.3%, 100.0%] | 0.0% [0.0%, 7.7%] | 25 ms | 525 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, +1.0] |
| ransomware | D9b DefySwarm minus sabotage triggers | 46 | 100.0% [92.3%, 100.0%] | 0.0% [0.0%, 7.7%] | 0 ms | 25 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| ransomware | D9c DefySwarm minus entropy/magic | 46 | 76.1% [62.1%, 86.1%] | 0.0% [0.0%, 7.7%] | 0 ms | 0 ms | 1 | 24 | 100.0% | <0.001 | 0.0 [0.0, 0.0] |
| ransomware | D9d DefySwarm minus swarm correlation | 46 | 100.0% [92.3%, 100.0%] | 0.0% [0.0%, 7.7%] | 0 ms | 25 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| ransomware | D9e DefySwarm minus honey credentials | 46 | 100.0% [92.3%, 100.0%] | 0.0% [0.0%, 7.7%] | 0 ms | 150 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| ransomware | D9f DefySwarm minus vault | 46 | 100.0% [92.3%, 100.0%] | 0.0% [0.0%, 7.7%] | 0 ms | 25 ms | 1 | 1 | 0.0% | 1.000 | 0.0 [0.0, 0.0] |

## Swarm

| Family | Detector | Traces | Detection rate (95% CI) | FP trace rate (95% CI) | Median TTD | p95 TTD | Median files lost | Worst files lost | Recoverable | McNemar p vs D9 | Median files-lost diff vs D9 [95% CI] |
| :--- | :--- | ---: | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| swarm | D0 No protection (versioning or nothing) | 36 | 0.0% [0.0%, 9.6%] | 0.0% [0.0%, 9.6%] | — | — | 18 | 24 | 52.8% | <0.001 | +17.0 [+11.0, +23.0] |
| swarm | D1 Snapshot / backup only | 36 | 0.0% [0.0%, 9.6%] | 0.0% [0.0%, 9.6%] | — | — | 18 | 24 | 100.0% | <0.001 | +17.0 [+11.0, +23.0] |
| swarm | D2 Per-principal behavioural anomaly | 36 | 0.0% [0.0%, 9.6%] | 0.0% [0.0%, 9.6%] | — | — | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +23.0] |
| swarm | D3 Per-principal batch rate rule | 36 | 44.4% [29.5%, 60.4%] | 0.0% [0.0%, 9.6%] | 57050 ms | 57750 ms | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +23.0] |
| swarm | D4 Malware / signature scan on upload | 36 | 27.8% [15.8%, 44.0%] | 0.0% [0.0%, 9.6%] | 0 ms | 0 ms | 12 | 24 | 0.0% | <0.001 | +11.0 [+11.0, +23.0] |
| swarm | D5 Sync-client ransomware heuristic | 36 | 0.0% [0.0%, 9.6%] | 0.0% [0.0%, 9.6%] | — | — | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +23.0] |
| swarm | D6 Extension and ransom-note blacklist | 36 | 0.0% [0.0%, 9.6%] | 0.0% [0.0%, 9.6%] | — | — | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +23.0] |
| swarm | D7 Naive fixed-name canary | 36 | 5.6% [1.5%, 18.1%] | 0.0% [0.0%, 9.6%] | 0 ms | 300 ms | 18 | 24 | 0.0% | <0.001 | +17.0 [+11.0, +23.0] |
| swarm | D8 Entropy-only threshold | 36 | 27.8% [15.8%, 44.0%] | 0.0% [0.0%, 9.6%] | 3000 ms | 32000 ms | 12 | 24 | 0.0% | <0.001 | +11.0 [+11.0, +23.0] |
| swarm | D9 DefySwarm full | 36 | 100.0% [90.4%, 100.0%] | 0.0% [0.0%, 9.6%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| swarm | D9a DefySwarm minus canaries | 36 | 100.0% [90.4%, 100.0%] | 0.0% [0.0%, 9.6%] | 0 ms | 500 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| swarm | D9b DefySwarm minus sabotage triggers | 36 | 100.0% [90.4%, 100.0%] | 0.0% [0.0%, 9.6%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| swarm | D9c DefySwarm minus entropy/magic | 36 | 86.1% [71.3%, 93.9%] | 0.0% [0.0%, 9.6%] | 0 ms | 0 ms | 1 | 24 | 100.0% | 0.063 | 0.0 [0.0, 0.0] |
| swarm | D9d DefySwarm minus swarm correlation | 36 | 100.0% [90.4%, 100.0%] | 0.0% [0.0%, 9.6%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| swarm | D9e DefySwarm minus honey credentials | 36 | 100.0% [90.4%, 100.0%] | 0.0% [0.0%, 9.6%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| swarm | D9f DefySwarm minus vault | 36 | 100.0% [90.4%, 100.0%] | 0.0% [0.0%, 9.6%] | 0 ms | 0 ms | 1 | 1 | 0.0% | 1.000 | 0.0 [0.0, 0.0] |

## Mixed

| Family | Detector | Traces | Detection rate (95% CI) | FP trace rate (95% CI) | Median TTD | p95 TTD | Median files lost | Worst files lost | Recoverable | McNemar p vs D9 | Median files-lost diff vs D9 [95% CI] |
| :--- | :--- | ---: | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| mixed | D0 No protection (versioning or nothing) | 30 | 0.0% [0.0%, 11.4%] | 0.0% [0.0%, 11.4%] | — | — | 20 | 20 | 100.0% | <0.001 | +19.0 [+19.0, +19.0] |
| mixed | D1 Snapshot / backup only | 30 | 0.0% [0.0%, 11.4%] | 0.0% [0.0%, 11.4%] | — | — | 20 | 20 | 100.0% | <0.001 | +19.0 [+19.0, +19.0] |
| mixed | D2 Per-principal behavioural anomaly | 30 | 73.3% [55.6%, 85.8%] | 0.0% [0.0%, 11.4%] | 0 ms | 18421 ms | 1 | 20 | 0.0% | 0.008 | 0.0 [0.0, +1.0] |
| mixed | D3 Per-principal batch rate rule | 30 | 63.3% [45.5%, 78.1%] | 0.0% [0.0%, 11.4%] | 36000 ms | 80500 ms | 9 | 20 | 0.0% | <0.001 | +8.0 [+8.0, +19.0] |
| mixed | D4 Malware / signature scan on upload | 30 | 73.3% [55.6%, 85.8%] | 0.0% [0.0%, 11.4%] | 0 ms | 500 ms | 1 | 20 | 0.0% | 0.008 | 0.0 [0.0, 0.0] |
| mixed | D5 Sync-client ransomware heuristic | 30 | 13.3% [5.3%, 29.7%] | 0.0% [0.0%, 11.4%] | 0 ms | 500 ms | 20 | 20 | 0.0% | <0.001 | +19.0 [+19.0, +19.0] |
| mixed | D6 Extension and ransom-note blacklist | 30 | 36.7% [21.9%, 54.5%] | 0.0% [0.0%, 11.4%] | 0 ms | 500 ms | 20 | 20 | 0.0% | <0.001 | +19.0 [0.0, +19.0] |
| mixed | D7 Naive fixed-name canary | 30 | 20.0% [9.5%, 37.3%] | 0.0% [0.0%, 11.4%] | 150 ms | 300 ms | 20 | 20 | 0.0% | <0.001 | +19.0 [+19.0, +19.0] |
| mixed | D8 Entropy-only threshold | 30 | 73.3% [55.6%, 85.8%] | 0.0% [0.0%, 11.4%] | 13263 ms | 92105 ms | 4 | 20 | 0.0% | 0.008 | +3.0 [+2.0, +5.0] |
| mixed | D9 DefySwarm full | 30 | 100.0% [88.6%, 100.0%] | 0.0% [0.0%, 11.4%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| mixed | D9a DefySwarm minus canaries | 30 | 100.0% [88.6%, 100.0%] | 0.0% [0.0%, 11.4%] | 0 ms | 500 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| mixed | D9b DefySwarm minus sabotage triggers | 30 | 100.0% [88.6%, 100.0%] | 0.0% [0.0%, 11.4%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| mixed | D9c DefySwarm minus entropy/magic | 30 | 46.7% [30.2%, 63.9%] | 0.0% [0.0%, 11.4%] | 0 ms | 0 ms | 20 | 20 | 100.0% | <0.001 | +19.0 [0.0, +19.0] |
| mixed | D9d DefySwarm minus swarm correlation | 30 | 100.0% [88.6%, 100.0%] | 0.0% [0.0%, 11.4%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| mixed | D9e DefySwarm minus honey credentials | 30 | 100.0% [88.6%, 100.0%] | 0.0% [0.0%, 11.4%] | 0 ms | 0 ms | 1 | 1 | 100.0% | 1.000 | 0.0 [0.0, 0.0] |
| mixed | D9f DefySwarm minus vault | 30 | 100.0% [88.6%, 100.0%] | 0.0% [0.0%, 11.4%] | 0 ms | 0 ms | 1 | 1 | 0.0% | 1.000 | 0.0 [0.0, 0.0] |

## Overall (all held-out traces)

| Detector | Traces | Attack traces | Detection rate (95% CI) | FP trace rate (95% CI) | Median TTD | p95 TTD | Median files lost | Worst files lost | Recoverable |
| :--- | ---: | ---: | :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| D0 No protection (versioning or nothing) | 162 | 112 | 0.0% [0.0%, 3.3%] | 0.0% [0.0%, 2.3%] | — | — | 20 | 24 | 77.7% |
| D1 Snapshot / backup only | 162 | 112 | 0.0% [0.0%, 3.3%] | 0.0% [0.0%, 2.3%] | — | — | 20 | 24 | 100.0% |
| D2 Per-principal behavioural anomaly | 162 | 112 | 25.9% [18.7%, 34.7%] | 0.0% [0.0%, 2.3%] | 0 ms | 40500 ms | 18 | 24 | 0.0% |
| D3 Per-principal batch rate rule | 162 | 112 | 58.9% [49.7%, 67.6%] | 0.0% [0.0%, 2.3%] | 57450 ms | 80000 ms | 18 | 24 | 0.0% |
| D4 Malware / signature scan on upload | 162 | 112 | 53.6% [44.4%, 62.5%] | 0.0% [0.0%, 2.3%] | 0 ms | 525 ms | 1 | 24 | 0.0% |
| D5 Sync-client ransomware heuristic | 162 | 112 | 8.9% [4.9%, 15.7%] | 0.0% [0.0%, 2.3%] | 0 ms | 525 ms | 18 | 24 | 0.0% |
| D6 Extension and ransom-note blacklist | 162 | 112 | 17.0% [11.1%, 25.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 500 ms | 18 | 24 | 0.0% |
| D7 Naive fixed-name canary | 162 | 112 | 19.6% [13.3%, 28.0%] | 0.0% [0.0%, 2.3%] | 150 ms | 300 ms | 18 | 24 | 0.0% |
| D8 Entropy-only threshold | 162 | 112 | 53.6% [44.4%, 62.5%] | 0.0% [0.0%, 2.3%] | 3000 ms | 37342 ms | 6 | 24 | 0.0% |
| D9 DefySwarm full | 162 | 112 | 100.0% [96.7%, 100.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 0 ms | 1 | 1 | 100.0% |
| D9a DefySwarm minus canaries | 162 | 112 | 100.0% [96.7%, 100.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 500 ms | 1 | 1 | 100.0% |
| D9b DefySwarm minus sabotage triggers | 162 | 112 | 100.0% [96.7%, 100.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 0 ms | 1 | 1 | 100.0% |
| D9c DefySwarm minus entropy/magic | 162 | 112 | 71.4% [62.5%, 79.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 0 ms | 1 | 24 | 100.0% |
| D9d DefySwarm minus swarm correlation | 162 | 112 | 100.0% [96.7%, 100.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 0 ms | 1 | 1 | 100.0% |
| D9e DefySwarm minus honey credentials | 162 | 112 | 100.0% [96.7%, 100.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 150 ms | 1 | 1 | 100.0% |
| D9f DefySwarm minus vault | 162 | 112 | 100.0% [96.7%, 100.0%] | 0.0% [0.0%, 2.3%] | 0 ms | 0 ms | 1 | 1 | 0.0% |

## Ablations (D9 minus one component)

| Detector | Component removed | Detection rate | FP trace rate | Median files lost | Δ detection vs D9 | Δ FP vs D9 |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| D9a | canaries | 100.0% | 0.0% | 1 | 0.0 pp | 0.0 pp |
| D9b | sabotage triggers | 100.0% | 0.0% | 1 | 0.0 pp | 0.0 pp |
| D9c | entropy/magic | 71.4% | 0.0% | 1 | -28.6 pp | 0.0 pp |
| D9d | swarm correlation | 100.0% | 0.0% | 1 | 0.0 pp | 0.0 pp |
| D9e | honey credentials | 100.0% | 0.0% | 1 | 0.0 pp | 0.0 pp |
| D9f | vault | 100.0% | 0.0% | 1 | 0.0 pp | 0.0 pp |

## Containment-latency sensitivity

Files lost as the post-detection containment latency L is swept. Every detector uses the same L in each row.

| L | Detector | Median files lost | Detection rate |
| ---: | :--- | ---: | ---: |
| 0 ms | D0 | 20 | 0.0% |
| 0 ms | D1 | 20 | 0.0% |
| 0 ms | D2 | 18 | 25.9% |
| 0 ms | D3 | 18 | 58.9% |
| 0 ms | D4 | 1 | 53.6% |
| 0 ms | D5 | 18 | 8.9% |
| 0 ms | D6 | 18 | 17.0% |
| 0 ms | D7 | 18 | 19.6% |
| 0 ms | D8 | 6 | 53.6% |
| 0 ms | D9 | 1 | 100.0% |
| 0 ms | D9a | 1 | 100.0% |
| 0 ms | D9b | 1 | 100.0% |
| 0 ms | D9c | 1 | 71.4% |
| 0 ms | D9d | 1 | 100.0% |
| 0 ms | D9e | 1 | 100.0% |
| 0 ms | D9f | 1 | 100.0% |
| 1000 ms | D0 | 20 | 0.0% |
| 1000 ms | D1 | 20 | 0.0% |
| 1000 ms | D2 | 18 | 25.9% |
| 1000 ms | D3 | 18 | 58.9% |
| 1000 ms | D4 | 6 | 53.6% |
| 1000 ms | D5 | 18 | 8.9% |
| 1000 ms | D6 | 18 | 17.0% |
| 1000 ms | D7 | 18 | 19.6% |
| 1000 ms | D8 | 8 | 53.6% |
| 1000 ms | D9 | 1 | 100.0% |
| 1000 ms | D9a | 1 | 100.0% |
| 1000 ms | D9b | 1 | 100.0% |
| 1000 ms | D9c | 1 | 71.4% |
| 1000 ms | D9d | 1 | 100.0% |
| 1000 ms | D9e | 1 | 100.0% |
| 1000 ms | D9f | 1 | 100.0% |
| 5000 ms | D0 | 20 | 0.0% |
| 5000 ms | D1 | 20 | 0.0% |
| 5000 ms | D2 | 18 | 25.9% |
| 5000 ms | D3 | 18 | 58.9% |
| 5000 ms | D4 | 12 | 53.6% |
| 5000 ms | D5 | 18 | 8.9% |
| 5000 ms | D6 | 18 | 17.0% |
| 5000 ms | D7 | 18 | 19.6% |
| 5000 ms | D8 | 12 | 53.6% |
| 5000 ms | D9 | 2 | 100.0% |
| 5000 ms | D9a | 2 | 100.0% |
| 5000 ms | D9b | 2 | 100.0% |
| 5000 ms | D9c | 4 | 71.4% |
| 5000 ms | D9d | 2 | 100.0% |
| 5000 ms | D9e | 2 | 100.0% |
| 5000 ms | D9f | 2 | 100.0% |
| 30000 ms | D0 | 20 | 0.0% |
| 30000 ms | D1 | 20 | 0.0% |
| 30000 ms | D2 | 18 | 25.9% |
| 30000 ms | D3 | 18 | 58.9% |
| 30000 ms | D4 | 18 | 53.6% |
| 30000 ms | D5 | 18 | 8.9% |
| 30000 ms | D6 | 18 | 17.0% |
| 30000 ms | D7 | 18 | 19.6% |
| 30000 ms | D8 | 18 | 53.6% |
| 30000 ms | D9 | 7 | 100.0% |
| 30000 ms | D9a | 7 | 100.0% |
| 30000 ms | D9b | 7 | 100.0% |
| 30000 ms | D9c | 12 | 71.4% |
| 30000 ms | D9d | 7 | 100.0% |
| 30000 ms | D9e | 7 | 100.0% |
| 30000 ms | D9f | 7 | 100.0% |
| 300000 ms | D0 | 20 | 0.0% |
| 300000 ms | D1 | 20 | 0.0% |
| 300000 ms | D2 | 18 | 25.9% |
| 300000 ms | D3 | 20 | 58.9% |
| 300000 ms | D4 | 18 | 53.6% |
| 300000 ms | D5 | 20 | 8.9% |
| 300000 ms | D6 | 18 | 17.0% |
| 300000 ms | D7 | 20 | 19.6% |
| 300000 ms | D8 | 18 | 53.6% |
| 300000 ms | D9 | 18 | 100.0% |
| 300000 ms | D9a | 18 | 100.0% |
| 300000 ms | D9b | 18 | 100.0% |
| 300000 ms | D9c | 18 | 71.4% |
| 300000 ms | D9d | 18 | 100.0% |
| 300000 ms | D9e | 18 | 100.0% |
| 300000 ms | D9f | 18 | 100.0% |

## Limitations

- Traces are generated by the seeded synthetic generator in eval/generator. They are not production telemetry.
- No recorded traces exist yet. Generator calibration is uncalibrated synthetic; see calibration.json.
- D0-D8 are our own reference implementations of common approaches, not vendor products.
- D5 (sync client) cannot see direct API-key attacks by construction; that is a threat-model difference, not a product failure.
- D9 uses the shipped data/policies.yaml unchanged. Baselines were tuned on the 30% tuning seed split to maximise detection subject to the same FP budget.
- The containment model blocks attacker events at detection + L. L is a post-detection latency, not a network round-trip measurement.
- Files lost counts distinct real files touched by labelled attack events before the block. Recoverable reports whether the detector has a recovery mechanism, not whether a specific restore was executed.
- Mixed-trace alert precision treats any alert before the labelled attack start as a false positive.
- Some D9 ablations are emulated at the event or policy boundary because policies.yaml cannot switch every component off independently. See docs/eval/BASELINES.md.
- No live external S3 endpoint, vendor product, or production data was used in the replay scorecard.

## Calibration

- No recorded traces exist yet. The scorecard is a synthetic-replay result and must be labelled that way when presented.
- Run "npm run eval:record" against a live simulator run, then "npm run eval:calibrate" to fit the generator.

## Run metadata

```
run id: eval-full-424242-761b9bcc41
date: 2026-11-22T00:36:50.977Z
mode: full
run seed: 424242
generation seed: 20261122
traces used: 162 (held-out), tuning traces: 48
path: replay
platform: darwin 27.0.0
node: v24.21.0
cpus: 10
memory: 16384 MB
product version: 0.0.0
detector implementation: D9: shipped server/detectionEngine.ts + server/storageAdapter.ts (fresh in-memory instance); D0-D8: eval/detectors/baselines.ts reference implementations
containment latency: 48 ms (live simulator MTTC median (8 runs))
determinism hash: c7a0a57706dde0c793bf2f9af47467eb6cf0aadee00b63d738ce9e13ec579bcc
```

Baselines are our own reference implementations of common approaches. They are not vendor products and were not supplied by any vendor. Where a baseline wins, the table says so. Where DefySwarm fails, the table says so.

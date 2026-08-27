# Advanced SIEM Correlation Detection Rules
**High-Fidelity | Low False-Positive | Real-Environment Ready**

**Version:** 1.0  
**Generated:** 2026-08-27  
**Audience:** SIEM Engineers, Threat Hunters, Detection Engineers

---

## Purpose

These are **correlation rules** (not single-event detections).  
They combine multiple signals across time and data sources so that alerts fire only when the pattern strongly indicates real attacker activity.

This dramatically reduces false positives compared with individual DET-xxx rules while increasing confidence for SOC response and automation.

## Contents

- **20 Advanced Correlation Rules** (CORR-001 → CORR-020)
- Step-by-step implementation guides for:
  - Microsoft Sentinel
  - Splunk
  - Elastic / ELK
- Mapping to base detections and Automated IR Playbooks

## Rule Design Principles

1. Multi-stage logic (at least two independent signals)
2. Explicit false-positive notes and tuning guidance
3. Time-bound windows to keep queries performant
4. Clear severity (High / Critical only)
5. Ready for linking to SOAR / Automated IR Playbooks

## Recommended Rollout

1. Deploy base DET-xxx rules first (previous package)
2. Implement CORR rules in **detection-only** mode
3. Validate true positives for 1–2 weeks
4. Enable alerting + automated response for Critical rules
5. Continuously tune thresholds and allow-lists

---

See `docs/` for platform-specific creation steps.

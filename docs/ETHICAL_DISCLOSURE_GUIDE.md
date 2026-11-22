# Coordinated Vulnerability Disclosure (CVD) Guide

## 1. Principles of Coordinated Disclosure
AegisForge adheres to established vulnerability handling guidelines (ISO/IEC 29147 and ISO/IEC 30111) to promote responsible remediation and transparent communication between researchers, maintainers, and asset owners.

Key principles include:
- **Harm Minimization**: All testing must be conducted exclusively against authorized assets or isolated local sandbox environments.
- **Timely Notice**: Maintainers should be notified promptly upon verification of a defect.
- **Remediation Window**: Maintainers are granted a standard 90-day grace period to investigate, patch, and deploy fixes prior to public advisory release.
- **Coordinated Publication**: Advisory releases should be synchronized to ensure patches or workarounds are readily available to end-users.

---

## 2. Disclosure Workflow Lifecycle

1. **Discovery & Triage**:
   - Verify the vulnerability in an isolated environment.
   - Calculate CVSS v3.1 metrics (Base, Temporal, Environmental).
   - Document minimal reproduction steps and affected components.

2. **Private Notification**:
   - Send initial encrypted advisory to the designated security contact.
   - Avoid disclosing details in public channels, issue trackers, or code commits.

3. **Validation & Patching**:
   - Maintainer acknowledges receipt within 3 business days.
   - Maintainer develops defensive remediation (e.g. bounded memory checks, compiler mitigation flags, permission adjustments).

4. **Advisory Release**:
   - Assign advisory tracking identifier (e.g. `AEGIS-YYYY-NNNN`).
   - Publish advisory documentation with clear mitigation guidance.

---

## 3. Project Security Contact Metadata Example

Projects adopting responsible disclosure can define a `security.txt` configuration:

```text
Contact: mailto:security@aegisforge.internal
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://aegisforge.internal/.well-known/security.txt
Policy: https://aegisforge.internal/security-policy
```

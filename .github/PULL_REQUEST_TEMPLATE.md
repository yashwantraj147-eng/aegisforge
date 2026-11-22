## Pull Request Overview

### Description
Provide a clear summary of the changes proposed in this Pull Request.

### Related Issues
Closes #[issue-number]

---

### Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking addition of a defensive/purple-team module capability)
- [ ] Documentation enhancement
- [ ] Performance improvement / Refactoring
- [ ] Test coverage addition

---

### Safety & Guardrail Compliance Checklist
*All contributions must pass our strict ethical safety guidelines before review.*
- [ ] **Target Boundary Check**: All network operations are strictly constrained to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or loopback. No external WAN targeting is enabled.
- [ ] **Benign Artifacts Only**: Zero live, infectious, or weaponized malware binaries or payloads are added. All test samples are synthetic or harmless standard signatures (e.g. EICAR).
- [ ] **Defense Paired**: Any offensive simulation feature is paired with a corresponding detection or mitigation mechanism.

---

### Quality Assurance & Verification
- [ ] All backend tests pass (`python -m pytest backend/tests -v`).
- [ ] Frontend builds cleanly with zero errors (`npm run build` in `frontend/`).
- [ ] Code formatting and linting pass (`ruff check backend/`).
- [ ] All new functions have appropriate type hints and documentation.

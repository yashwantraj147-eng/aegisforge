import pytest
from backend.app.engines.fuzz_re import StatefulProtocolFuzzer, WindowsACLAuditor, StaticBinaryAuditor
from backend.app.models.schemas import ProtocolFuzzRequest, ACLAuditRequest, BinaryAuditRequest

@pytest.mark.asyncio
async def test_protocol_fuzzing_simulation():
    fuzzer = StatefulProtocolFuzzer()
    req = ProtocolFuzzRequest(
        target_host="127.0.0.1",
        target_port=5000,
        max_cases=50,
        mutation_strategies=["OVERSIZE_BUFFER", "FORMAT_STRING", "BOUNDARY_INTEGER"]
    )
    res = await fuzzer.run_fuzzing_campaign(req)

    assert res.total_cases_run == 50
    assert res.cases_per_second > 0
    assert len(res.test_cases) > 0
    # Crashes should be caught for deterministic vectors
    assert res.crashes_detected > 0
    assert len(res.unique_crashes) > 0
    for crash in res.unique_crashes:
        assert "RIP" in crash.registers_snapshot

def test_windows_acl_auditor():
    auditor = WindowsACLAuditor()
    sample_policy = {
        "rules": [
            {
                "path": "C:\\Windows\\System32\\mock_service.exe",
                "principal": "Everyone",
                "permission": "FullControl",
                "type": "Allow"
            },
            {
                "path": "C:\\Program Files\\AegisLab\\config.ini",
                "principal": "BUILTIN\\Users",
                "permission": "WriteData",
                "type": "Allow"
            },
            {
                "path": "C:\\Windows\\safe.dll",
                "principal": "NT AUTHORITY\\SYSTEM",
                "permission": "FullControl",
                "type": "Allow"
            }
        ]
    }
    req = ACLAuditRequest(policy_json=sample_policy)
    res = auditor.audit_policy(req)

    assert res.total_rules_analyzed == 3
    assert res.high_risk_findings == 2
    # Verify critical finding on System32
    paths = [f.target_path for f in res.findings]
    assert "C:\\Windows\\System32\\mock_service.exe" in paths
    assert "icacls" in res.findings[0].remediation_cmd

def test_static_binary_auditor_elf():
    req = BinaryAuditRequest(filename="sample_synthetic.elf")
    res = StaticBinaryAuditor.audit_binary(req)

    assert "ELF" in res.binary_format
    assert "x86_64" in res.architecture
    assert len(res.sections) > 0
    assert res.security_score >= 0.0
    assert res.verdict in ["HARDENED", "MODERATE_PROTECTION", "VULNERABLE_UNHARDENED"]

def test_static_binary_auditor_pe():
    req = BinaryAuditRequest(filename="sample_synthetic.exe")
    res = StaticBinaryAuditor.audit_binary(req)

    assert "PE" in res.binary_format
    assert len(res.sections) > 0
    assert res.mitigations is not None

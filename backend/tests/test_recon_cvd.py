import pytest
from backend.app.engines.recon_cvd import ReconEngine, CVSSv31Calculator, CVDReportGenerator
from backend.app.models.schemas import PortScanRequest, CVSSCalculationRequest, CVDReportRequest
from backend.app.core.safety_guard import SafetyViolationException

@pytest.mark.asyncio
async def test_recon_scan_simulation_mode():
    engine = ReconEngine()
    req = PortScanRequest(target="192.168.100.105", start_port=20, end_port=100)
    res = await engine.scan_target(req)

    assert res.target == "192.168.100.105"
    assert res.scope_verified is True
    assert res.open_ports_count > 0
    # Port 22 and 80 should be open in mock
    open_ports = [p.port for p in res.open_ports]
    assert 22 in open_ports
    assert 80 in open_ports

@pytest.mark.asyncio
async def test_recon_scan_safety_guard_blocks_wan():
    engine = ReconEngine()
    req = PortScanRequest(target="8.8.8.8", start_port=53, end_port=53)
    with pytest.raises(SafetyViolationException):
        await engine.scan_target(req)

def test_cvss_v31_calculation_critical():
    calc = CVSSv31Calculator()
    # Canonical CVSS 9.8 Critical vector
    req = CVSSCalculationRequest(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="UNCHANGED",
        confidentiality="HIGH",
        integrity="HIGH",
        availability="HIGH"
    )
    res = calc.calculate(req)
    assert res.base_score == 9.8
    assert res.severity_rating == "CRITICAL"
    assert "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in res.vector_string

def test_cvss_v31_calculation_vector_string_parsing():
    calc = CVSSv31Calculator()
    req = CVSSCalculationRequest(vector_string="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    res = calc.calculate(req)
    assert res.severity_rating == "LOW"
    assert res.base_score <= 3.9

def test_cvd_report_generation():
    req = CVDReportRequest(
        advisory_id="AEGIS-2026-TEST",
        vulnerability_title="Test Stack Buffer Overflow in TestLab",
        affected_component="TestLab v1.0",
        summary="Educational memory buffer overflow test.",
        technical_description="Unbounded strcpy call in stack frame.",
        reproduction_steps=["Step 1: Input 64 bytes", "Step 2: Observe crash"],
        remediation_recommendations=["Use strncpy", "Enable -fstack-protector"],
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=8.4,
        severity="HIGH"
    )
    res = CVDReportGenerator.generate(req)
    assert res.advisory_id == "AEGIS-2026-TEST"
    assert "# Coordinated Vulnerability Disclosure Advisory" in res.markdown_content
    assert "AEGIS-2026-TEST" in res.html_content
    assert "8.4" in res.markdown_content

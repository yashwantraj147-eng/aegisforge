from typing import Optional
from fastapi import APIRouter, HTTPException, status
from backend.app.core.safety_guard import SafetyViolationException
from backend.app.core.ws_manager import ws_manager
from backend.app.models.schemas import (
    PortScanRequest, ScanResultResponse, ScopeVerificationRequest, ScopeVerificationResponse,
    CVSSCalculationRequest, CVSSCalculationResponse,
    CVDReportRequest, CVDReportResponse
)
from backend.app.engines.recon_cvd import recon_engine, cvss_calculator, cvd_report_generator

router = APIRouter(prefix="/recon", tags=["Module 1: Recon & CVD"])

@router.post("/scope", response_model=ScopeVerificationResponse)
def verify_scope(body: Optional[ScopeVerificationRequest] = None, target: Optional[str] = None):
    """Verifies target IP, CIDR, or hostname against strict RFC1918/localhost guardrails."""
    t = (body.target if body and body.target else None) or target or "127.0.0.1"
    return recon_engine.verify_target_scope(t)

@router.post("/scan", response_model=ScanResultResponse)
async def scan_target(req: PortScanRequest):
    """Runs a scoped port and service banner discovery scan."""
    try:
        result = await recon_engine.scan_target(req)
        await ws_manager.broadcast_event(
            module="RECON",
            event_type="SCAN_COMPLETED",
            severity="INFO",
            message=f"Recon scan completed for {req.target}. Discovered {result.open_ports_count} open service(s).",
            data={"target": req.target, "open_ports": [p.port for p in result.open_ports]}
        )
        return result
    except SafetyViolationException as e:
        await ws_manager.broadcast_event(
            module="SAFETY_GUARD",
            event_type="BLOCKED_SCAN",
            severity="HIGH",
            message=e.message,
            data={"target": e.target}
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

@router.post("/cvss", response_model=CVSSCalculationResponse)
def calculate_cvss(req: CVSSCalculationRequest):
    """Calculates official FIRST CVSS v3.1 base score, severity rating, and vector string."""
    return cvss_calculator.calculate(req)

@router.post("/report", response_model=CVDReportResponse)
async def generate_cvd_report(req: CVDReportRequest):
    """Generates an RFC 9116 / ISO 29147 compliant Coordinated Vulnerability Disclosure advisory."""
    res = cvd_report_generator.generate(req)
    await ws_manager.broadcast_event(
        module="CVD",
        event_type="ADVISORY_GENERATED",
        severity="MEDIUM",
        message=f"CVD Advisory published: {req.advisory_id} ({req.severity} - CVSS {req.cvss_score})",
        data={"advisory_id": req.advisory_id, "score": req.cvss_score}
    )
    return res

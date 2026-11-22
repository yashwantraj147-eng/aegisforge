from fastapi import APIRouter, HTTPException, status
from backend.app.core.safety_guard import SafetyViolationException
from backend.app.core.ws_manager import ws_manager
from backend.app.core.database import db
from backend.app.core.metrics import metrics
from backend.app.engines.fuzz_re import fuzz_engine, acl_auditor, binary_auditor
from backend.app.models.schemas import (
    ProtocolFuzzRequest, ProtocolFuzzResponse,
    ACLAuditRequest, ACLAuditResponse,
    BinaryAuditRequest, BinaryAuditResponse
)

router = APIRouter(prefix="/fuzz", tags=["Module 4: Protocol Fuzzing & Static Policy Audit"])

@router.post("/protocol", response_model=ProtocolFuzzResponse)
async def fuzz_protocol(req: ProtocolFuzzRequest):
    """Executes stateful protocol fuzzing campaign with mutation strategies and crash isolation."""
    try:
        result = await fuzz_engine.run_fuzzing_campaign(req)
        await db.save_fuzz(req.target_host, result.total_cases_run, result.unique_crashes)
        metrics.record_fuzz(result.total_cases_run, result.crashes_detected)
        severity = "CRITICAL" if result.crashes_detected > 0 else "INFO"
        await ws_manager.broadcast_event(
            module="FUZZING",
            event_type="FUZZ_CAMPAIGN_COMPLETED",
            severity=severity,
            message=f"Fuzzing run completed against {result.target}: {result.total_cases_run} cases executed ({result.cases_per_second} cps). Detected {result.crashes_detected} crash(es).",
            data={"crashes": result.crashes_detected, "target": result.target}
        )
        return result
    except SafetyViolationException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.post("/acl-audit", response_model=ACLAuditResponse)
def audit_acl(req: ACLAuditRequest):
    """Audits Windows Security Descriptor / ACL JSON policies to identify privilege escalation vulnerabilities."""
    try:
        return acl_auditor.audit_policy(req)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.post("/binary-audit", response_model=BinaryAuditResponse)
def audit_binary(req: BinaryAuditRequest):
    """Statically audits ELF or PE binary headers and compiler mitigations (Canary, NX, PIE, ASLR, RELRO)."""
    try:
        return binary_auditor.audit_binary(req)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

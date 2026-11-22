from fastapi import APIRouter, HTTPException, status
from backend.app.core.config import settings
from backend.app.core.ws_manager import ws_manager
from backend.app.core.safety_guard import safety_guard
from backend.app.engines.mal_triage import malware_triage_engine
from backend.app.models.schemas import TriageArtifactRequest, MalwareTriageResponse

router = APIRouter(prefix="/maltriage", tags=["Module 5: Malware & Benign Artifact Triage"])

@router.post("/analyze", response_model=MalwareTriageResponse)
async def analyze_artifact(req: TriageArtifactRequest):
    """Triages a safe test artifact: Shannon entropy, printable strings, regex IOCs, YARA, and MITRE ATT&CK."""
    try:
        if req.content_raw_hex:
            safety_guard.validate_payload_size(req.content_raw_hex, max_bytes=settings.MAX_PAYLOAD_BYTES, field_name="content_raw_hex")
        res = malware_triage_engine.triage_artifact(req)
        severity = "CRITICAL" if res.risk_score >= 8.0 else ("HIGH" if res.risk_score >= 6.0 else "INFO")
        await ws_manager.broadcast_event(
            module="MAL_TRIAGE",
            event_type="TRIAGE_COMPLETED",
            severity=severity,
            message=f"Artifact '{req.filename}' triaged: Entropy {res.overall_entropy:.2f}, {len(res.yara_matches)} YARA hit(s), Verdict: {res.verdict}",
            data={"filename": req.filename, "verdict": res.verdict, "score": res.risk_score}
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/samples")
def list_available_samples():
    """Lists safe pre-generated test artifacts available in the sandbox directory."""
    artifacts_dir = settings.SAMPLE_ARTIFACTS_PATH
    sample_files = []
    if artifacts_dir.exists():
        for f in artifacts_dir.glob("*.*"):
            sample_files.append({
                "filename": f.name,
                "size_bytes": f.stat().st_size,
                "description": "Benign synthetic test artifact for laboratory verification"
            })
    return {
        "samples_directory": str(artifacts_dir),
        "available_samples": sample_files
    }

import asyncio
import socket
import time
import math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from backend.app.core.config import settings, ExecutionMode
from backend.app.core.safety_guard import safety_guard, SafetyViolationException
from backend.app.models.schemas import (
    PortScanRequest, DiscoveredPort, ScanResultResponse,
    ScopeVerificationResponse, CVSSCalculationRequest, CVSSCalculationResponse,
    CVDReportRequest, CVDReportResponse
)

# Known mock laboratory service signatures
MOCK_LAB_SERVICES = {
    21: ("FTP", "vsftpd 2.3.4 (Backdoor Lab Target)", ["CVE-2011-2523"]),
    22: ("SSH", "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6", ["CVE-2023-38408"]),
    80: ("HTTP", "nginx/1.18.0 (Ubuntu) - Mock Aegis Dashboard", []),
    443: ("HTTPS", "nginx/1.18.0 (Ubuntu) TLS 1.3", []),
    5000: ("MiniProto", "MiniProto Stateful TCP Service v1.0", ["CVE-2026-MOCK-001"]),
    8080: ("HTTP-Proxy", "Apache Tomcat/9.0.58", ["CVE-2022-22965"]),
    3306: ("MySQL", "5.7.38-0ubuntu0.18.04.1", []),
    6379: ("Redis", "Redis key-value store 6.0.16", ["CVE-2022-0543"])
}

class CVSSv31Calculator:
    """
    Standard FIRST CVSS v3.1 Metric Calculator.
    Calculates exact base scores and vector strings according to CVSS v3.1 Specification.
    """
    # Base Metric Weights
    AV_WEIGHTS = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20}
    AC_WEIGHTS = {"LOW": 0.77, "HIGH": 0.44}
    PR_WEIGHTS = {
        "UNCHANGED": {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27},
        "CHANGED": {"NONE": 0.85, "LOW": 0.68, "HIGH": 0.50}
    }
    UI_WEIGHTS = {"NONE": 0.85, "REQUIRED": 0.62}
    CIA_WEIGHTS = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

    @staticmethod
    def _roundup(val: float) -> float:
        """CVSS v3.1 Roundup specification."""
        int_val = round(val * 100000)
        if int_val % 10000 == 0:
            return int_val / 100000.0
        return (math.floor(int_val / 10000) + 1) / 10.0

    @classmethod
    def calculate(cls, req: CVSSCalculationRequest) -> CVSSCalculationResponse:
        # If vector string provided, parse metrics from vector
        metrics = {
            "AV": req.attack_vector.upper(),
            "AC": req.attack_complexity.upper(),
            "PR": req.privileges_required.upper(),
            "UI": req.user_interaction.upper(),
            "S": req.scope.upper(),
            "C": req.confidentiality.upper(),
            "I": req.integrity.upper(),
            "A": req.availability.upper()
        }

        if req.vector_string and "CVSS:3.1" in req.vector_string:
            parts = req.vector_string.strip().split("/")
            for p in parts[1:]:
                if ":" in p:
                    k, v = p.split(":", 1)
                    if k == "AV": metrics["AV"] = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}.get(v, metrics["AV"])
                    elif k == "AC": metrics["AC"] = {"L": "LOW", "H": "HIGH"}.get(v, metrics["AC"])
                    elif k == "PR": metrics["PR"] = {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(v, metrics["PR"])
                    elif k == "UI": metrics["UI"] = {"N": "NONE", "R": "REQUIRED"}.get(v, metrics["UI"])
                    elif k == "S": metrics["S"] = {"U": "UNCHANGED", "C": "CHANGED"}.get(v, metrics["S"])
                    elif k == "C": metrics["C"] = {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(v, metrics["C"])
                    elif k == "I": metrics["I"] = {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(v, metrics["I"])
                    elif k == "A": metrics["A"] = {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(v, metrics["A"])

        scope = metrics["S"]
        av = cls.AV_WEIGHTS.get(metrics["AV"], 0.85)
        ac = cls.AC_WEIGHTS.get(metrics["AC"], 0.77)
        pr = cls.PR_WEIGHTS[scope].get(metrics["PR"], 0.85)
        ui = cls.UI_WEIGHTS.get(metrics["UI"], 0.85)
        c = cls.CIA_WEIGHTS.get(metrics["C"], 0.56)
        i = cls.CIA_WEIGHTS.get(metrics["I"], 0.56)
        a = cls.CIA_WEIGHTS.get(metrics["A"], 0.56)

        # ISS = 1 - [ (1 - C) * (1 - I) * (1 - A) ]
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Impact Sub score
        if scope == "UNCHANGED":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Exploitability Sub score
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0.0
        else:
            if scope == "UNCHANGED":
                base_score = cls._roundup(min(impact + exploitability, 10.0))
            else:
                base_score = cls._roundup(min(1.08 * (impact + exploitability), 10.0))

        # Severity mapping
        if base_score == 0.0:
            rating = "NONE"
        elif base_score <= 3.9:
            rating = "LOW"
        elif base_score <= 6.9:
            rating = "MEDIUM"
        elif base_score <= 8.9:
            rating = "HIGH"
        else:
            rating = "CRITICAL"

        # Build official vector string
        av_code = {"NETWORK": "N", "ADJACENT": "A", "LOCAL": "L", "PHYSICAL": "P"}[metrics["AV"]]
        ac_code = {"LOW": "L", "HIGH": "H"}[metrics["AC"]]
        pr_code = {"NONE": "N", "LOW": "L", "HIGH": "H"}[metrics["PR"]]
        ui_code = {"NONE": "N", "REQUIRED": "R"}[metrics["UI"]]
        s_code = {"UNCHANGED": "U", "CHANGED": "C"}[metrics["S"]]
        c_code = {"NONE": "N", "LOW": "L", "HIGH": "H"}[metrics["C"]]
        i_code = {"NONE": "N", "LOW": "L", "HIGH": "H"}[metrics["I"]]
        a_code = {"NONE": "N", "LOW": "L", "HIGH": "H"}[metrics["A"]]

        vector_str = f"CVSS:3.1/AV:{av_code}/AC:{ac_code}/PR:{pr_code}/UI:{ui_code}/S:{s_code}/C:{c_code}/I:{i_code}/A:{a_code}"

        return CVSSCalculationResponse(
            base_score=round(base_score, 1),
            severity_rating=rating,
            vector_string=vector_str,
            metrics_breakdown=metrics,
            formula_components={
                "iss": round(iss, 4),
                "impact": round(impact, 4),
                "exploitability": round(exploitability, 4)
            }
        )

class ReconEngine:
    """
    ToE (Target of Evaluation) Scope Mapper & Local Lab Service Scanner.
    Strictly enforces SafetyGuard before issuing any socket probe.
    """
    def __init__(self):
        self.safety_guard = safety_guard

    def verify_target_scope(self, target: str) -> ScopeVerificationResponse:
        try:
            self.safety_guard.validate_target(target)
            return ScopeVerificationResponse(
                target=target,
                is_authorized=True,
                scope_classification="AUTHORIZED_LAB_SCOPE",
                guardrail_note="Target adheres strictly to RFC1918/Localhost boundaries."
            )
        except SafetyViolationException as e:
            return ScopeVerificationResponse(
                target=target,
                is_authorized=False,
                scope_classification="UNAUTHORIZED_WAN_TARGET",
                guardrail_note=e.message
            )

    async def scan_target(self, req: PortScanRequest) -> ScanResultResponse:
        # Step 1: Mandatory Safety Validation
        self.safety_guard.validate_target(req.target)
        self.safety_guard.validate_port_range(req.start_port, req.end_port)

        start_time = time.perf_counter()
        discovered_ports: List[DiscoveredPort] = []

        # Dual Execution Mode Handling
        if settings.MODE == ExecutionMode.SIMULATION:
            # Deterministic simulation tailored to specific lab nodes
            target_clean = req.target.strip()
            if target_clean in ["192.168.100.1", "gateway.aegis.internal"]:
                node_services = {
                    53: ("DNS", "Unbound 1.16.2 Lab Gateway DNS", []),
                    80: ("HTTP", "OpenWrt LuCI 21.02 Gateway Web Interface", []),
                    443: ("HTTPS", "OpenWrt uHTTPd TLS 1.3", [])
                }
            elif target_clean in ["192.168.100.105", "victim.aegis.internal"]:
                node_services = {
                    22: ("SSH", "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6", ["CVE-2023-38408"]),
                    80: ("HTTP", "nginx/1.18.0 (Ubuntu) - Mock Victim Dashboard", []),
                    5000: ("MiniProto", "MiniProto Stateful TCP Service v1.0", ["CVE-2026-MOCK-001"])
                }
            elif target_clean in ["192.168.100.200", "monitor.aegis.internal"]:
                node_services = {
                    5000: ("MiniProto", "MiniProto Stateful TCP Service v1.0 (Sandbox)", ["CVE-2026-MOCK-001"]),
                    8080: ("HTTP-Proxy", "Aegis Monitor Telemetry Collector v1.0", [])
                }
            else:
                node_services = MOCK_LAB_SERVICES

            for p, (srv, banner, cves) in node_services.items():
                if req.start_port <= p <= req.end_port:
                    discovered_ports.append(
                        DiscoveredPort(
                            port=p,
                            protocol="TCP",
                            state="OPEN",
                            service=srv,
                            banner=banner,
                            cve_hints=cves
                        )
                    )
            await asyncio.sleep(0.05)  # Slight yield for UI responsiveness
            total_probed = max(req.end_port - req.start_port + 1, len(discovered_ports))
        else:
            # DOCKER_LIVE mode: Non-blocking async TCP connect probe
            total_probed = 0
            tasks = []
            # Bound live scan batch to 200 ports for performance & safety
            scan_end = min(req.end_port, req.start_port + 200)

            async def probe_port(port: int):
                nonlocal total_probed
                total_probed += 1
                try:
                    conn = asyncio.open_connection(req.target, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=0.3)
                    banner = None
                    try:
                        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                        await asyncio.wait_for(writer.drain(), timeout=0.2)
                        data = await asyncio.wait_for(reader.read(128), timeout=0.3)
                        banner = data.decode(errors="ignore").strip().split("\r\n")[0]
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                    service_name = MOCK_LAB_SERVICES.get(port, ("TCP-Service", "", []))[0]
                    discovered_ports.append(
                        DiscoveredPort(
                            port=port,
                            protocol="TCP",
                            state="OPEN",
                            service=service_name,
                            banner=banner or f"Open TCP Port {port}",
                            cve_hints=[]
                        )
                    )
                except Exception:
                    pass

            for port in range(req.start_port, scan_end + 1):
                tasks.append(probe_port(port))
            await asyncio.gather(*tasks, return_exceptions=True)

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return ScanResultResponse(
            target=req.target,
            scan_duration_ms=round(duration_ms, 2),
            total_ports_probed=total_probed,
            open_ports_count=len(discovered_ports),
            open_ports=discovered_ports,
            scope_verified=True,
            mode=settings.MODE.value
        )

class CVDReportGenerator:
    """
    Coordinated Vulnerability Disclosure (CVD) Report Generator.
    Adheres to ISO/IEC 29147, ISO/IEC 30111, and RFC 9116 guidance.
    """
    @staticmethod
    def generate(req: CVDReportRequest) -> CVDReportResponse:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build timeline bullets
        timeline_md = ""
        timeline_html = ""
        for date_k, event_v in req.disclosure_timeline.items():
            timeline_md += f"- **{date_k}**: {event_v}\n"
            timeline_html += f"<li><strong>{date_k}</strong>: {event_v}</li>"
        if not timeline_md:
            timeline_md = f"- **{now_str[:10]}**: Initial discovery & internal verification.\n- **{now_str[:10]}**: Coordinated advisory drafted.\n"
            timeline_html = f"<li><strong>{now_str[:10]}</strong>: Initial discovery & internal verification.</li><li><strong>{now_str[:10]}</strong>: Coordinated advisory drafted.</li>"

        # Markdown Report
        markdown = f"""# Coordinated Vulnerability Disclosure Advisory
**Advisory ID:** `{req.advisory_id}`  
**Severity:** `{req.severity}` (CVSS v3.1: **{req.cvss_score}**)  
**Vector:** `{req.cvss_vector}`  
**Affected Component:** `{req.affected_component}`  
**Date Published:** {now_str}  
**Reporter:** `{req.reporter_contact}`  

---

## 1. Executive Summary
{req.summary}

## 2. Target Environment
- **Environment:** {req.target_environment}
- **Boundary Verification:** Compliant with isolated RFC1918 sandbox constraints.

## 3. Technical Vulnerability Analysis
{req.technical_description}

### Reproduction Steps
"""
        for idx, step in enumerate(req.reproduction_steps, 1):
            markdown += f"{idx}. {step}\n"

        markdown += """
## 4. Remediation & Patch Guidance
"""
        for r in req.remediation_recommendations:
            markdown += f"- [x] {r}\n"

        markdown += f"""
## 5. Disclosure Timeline
{timeline_md}

---
*Generated automatically by AegisForge Coordinated Vulnerability Disclosure Engine (RFC 9116 Compliant).*
"""

        # HTML Report
        repro_li = "".join([f"<li>{s}</li>" for s in req.reproduction_steps])
        remed_li = "".join([f"<li>{r}</li>" for r in req.remediation_recommendations])

        html = f"""<div class="cvd-advisory font-sans bg-slate-900 text-slate-100 p-6 rounded-lg border border-slate-700">
  <div class="flex justify-between items-center border-b border-slate-800 pb-4 mb-4">
    <div>
      <span class="px-2 py-1 text-xs font-semibold rounded bg-red-950 text-red-400 border border-red-800">{req.severity}</span>
      <h2 class="text-xl font-bold mt-2 text-white">{req.advisory_id}: {req.vulnerability_title}</h2>
    </div>
    <div class="text-right text-sm text-slate-400">
      <div>CVSS Score: <span class="font-mono font-bold text-red-400">{req.cvss_score}</span></div>
      <div class="text-xs font-mono">{req.cvss_vector}</div>
    </div>
  </div>
  <div class="space-y-4">
    <div>
      <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">Summary</h3>
      <p class="text-sm text-slate-300 mt-1">{req.summary}</p>
    </div>
    <div>
      <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">Technical Details</h3>
      <p class="text-sm text-slate-300 mt-1">{req.technical_description}</p>
    </div>
    <div>
      <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">Reproduction Steps</h3>
      <ol class="list-decimal list-inside text-sm text-slate-300 mt-1 space-y-1">{repro_li}</ol>
    </div>
    <div>
      <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">Remediation Recommendations</h3>
      <ul class="list-disc list-inside text-sm text-emerald-400 mt-1 space-y-1">{remed_li}</ul>
    </div>
    <div>
      <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">Disclosure Timeline</h3>
      <ul class="list-disc list-inside text-xs text-slate-400 mt-1 space-y-1">{timeline_html}</ul>
    </div>
  </div>
</div>"""

        return CVDReportResponse(
            advisory_id=req.advisory_id,
            markdown_content=markdown,
            html_content=html,
            json_metadata={
                "advisory_id": req.advisory_id,
                "cvss_vector": req.cvss_vector,
                "cvss_score": req.cvss_score,
                "severity": req.severity,
                "affected_component": req.affected_component,
                "generated_at": now_str
            },
            generated_at=now_str
        )

recon_engine = ReconEngine()
cvss_calculator = CVSSv31Calculator()
cvd_report_generator = CVDReportGenerator()

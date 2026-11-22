import asyncio
import json
import random
import socket
import struct
import time
from typing import List, Dict, Any, Union, Optional

from backend.app.core.config import settings, ExecutionMode
from backend.app.core.safety_guard import safety_guard
from backend.app.core.utils import calculate_shannon_entropy
from backend.app.core.logger import get_logger
from backend.app.models.schemas import (

logger = get_logger("fuzz_re")
    ProtocolFuzzRequest, ProtocolFuzzResponse, FuzzTestCase, FuzzCrashReport,
    ACLAuditRequest, ACLAuditResponse, ACLFinding,
    BinaryAuditRequest, BinaryAuditResponse, BinarySectionInfo, BinaryMitigations
)

class StatefulProtocolFuzzer:
    """
    Module 4: Generation-Based Stateful Protocol Fuzzer & Crash Triage.
    Fuzzes stateful network protocol implementations (e.g. MiniProto or HTTP/TCP)
    using multiple mutation and boundary probing strategies.
    """
    MUTATION_TEMPLATES = {
        "BIT_FLIP": [
            b"AUTH admin:\x80\xff\x00secret\r\n",
            b"SET user_session_\xfe\x01 = 99999\r\n",
            b"PING \xff\xff\xfe\x00\r\n"
        ],
        "BOUNDARY_INTEGER": [
            b"SET_CHUNK_SIZE -1\r\n",
            b"SET_CHUNK_SIZE 0\r\n",
            b"SET_CHUNK_SIZE 65535\r\n",
            b"SET_CHUNK_SIZE 2147483647\r\n",  # INT_MAX
            b"SET_CHUNK_SIZE 4294967295\r\n"   # UINT_MAX
        ],
        "FORMAT_STRING": [
            b"ECHO %s%s%s%s%s%s%s%s%n\r\n",
            b"AUTH user_%x_%08x_%p\r\n",
            b"LOG %08x.%08x.%08x.%08x\r\n"
        ],
        "OVERSIZE_BUFFER": [
            b"HELO " + b"A" * 256 + b"\r\n",
            b"AUTH " + b"A" * 1024 + b"\r\n",
            b"STORE_PAYLOAD " + b"A" * 2048 + b"\r\n"
        ],
        "DELIMITER_INJECTION": [
            b"\r\n\r\n\r\n\r\n",
            b"DATA \x00\x00\x00\x00\r\n",
            b"GET /api/v1/test HTTP/1.1\r\nHost: \x00.internal\r\n\r\n",
            b"CMD \t\t\t\x0b\x0c\r\n"
        ]
    }

    @staticmethod
    def _simulate_proto_response(payload: bytes) -> tuple[int, str, bool, Optional[Dict[str, str]]]:
        """
        Simulates stateful parser behavior and identifies crash vectors deterministically.
        Returns: (status_code, status_str, is_crash, registers_snapshot)
        """
        # Deterministic Crash Condition 1: Oversize buffer >= 1024 bytes
        if len(payload) >= 1024 and b"A" * 512 in payload:
            regs = {
                "RIP": "0x4141414141414141",
                "RBP": "0x4141414141414141",
                "RSP": "0x00007fffffffe120",
                "RAX": "0x0000000000000000",
                "RDI": "0x0000000000000400",
                "EFLAGS": "0x00010206 [CF PF IF]"
            }
            return 500, "CRASH", True, regs

        # Deterministic Crash Condition 2: Format string with %n write primitive
        if b"%n" in payload:
            regs = {
                "RIP": "0x00007ffff7e089f2 (vfprintf)",
                "RBP": "0x00007fffffffe200",
                "RSP": "0x00007fffffffe1a0",
                "RAX": "0x0000000000000018",
                "EFLAGS": "0x00010246 [ZF PF IF]"
            }
            return 500, "CRASH", True, regs

        # Deterministic Crash Condition 3: Signed integer overflow (INT_MAX boundary)
        if b"2147483647" in payload:
            regs = {
                "RIP": "0x000055555555523a (handle_chunk)",
                "RBP": "0x00007fffffffe310",
                "RSP": "0x00007fffffffe2f0",
                "RAX": "0x80000000 (-2147483648 overflow)",
                "EFLAGS": "0x00010886 [OF SF IF]"
            }
            return 500, "CRASH", True, regs

        # Edge error
        if b"\x00" in payload or b"-1" in payload:
            return 400, "SERVER_ERROR", False, None

        return 200, "PASS", False, None

    async def run_fuzzing_campaign(self, req: ProtocolFuzzRequest) -> ProtocolFuzzResponse:
        # Step 1: Validate target against safety guard
        safety_guard.validate_target(req.target_host)
        safety_guard.validate_port_range(req.target_port, req.target_port)

        start_time = time.perf_counter()
        test_cases: List[FuzzTestCase] = []
        crashes: List[FuzzCrashReport] = []

        total_cases = req.max_cases
        strategies = req.mutation_strategies or list(self.MUTATION_TEMPLATES.keys())

        for case_idx in range(1, total_cases + 1):
            strat = random.choice(strategies)
            templates = self.MUTATION_TEMPLATES.get(strat, [b"TEST\r\n"])
            base_payload = random.choice(templates)

            # Slight mutation
            if strat == "BIT_FLIP" and len(base_payload) > 4:
                idx = random.randint(0, len(base_payload) - 2)
                mutated = bytearray(base_payload)
                mutated[idx] ^= (1 << random.randint(0, 7))
                payload = bytes(mutated)
            elif strat == "OVERSIZE_BUFFER":
                # Scale buffer size across run
                scale = random.choice([256, 512, 1024, 2048])
                payload = b"STORE " + (b"A" * scale) + b"\r\n"
            else:
                payload = base_payload

            # Execute case
            case_start = time.perf_counter()
            if settings.MODE == ExecutionMode.SIMULATION:
                # Deterministic simulation
                await asyncio.sleep(0.001)  # Micro-yield
                status_code, status_str, is_crash, regs = self._simulate_proto_response(payload)
                latency_ms = (time.perf_counter() - case_start) * 1000.0 + random.uniform(0.2, 1.8)
            else:
                # DOCKER_LIVE mode: socket probe
                try:
                    conn = asyncio.open_connection(req.target_host, req.target_port)
                    reader, writer = await asyncio.wait_for(conn, timeout=0.5)
                    writer.write(payload)
                    await asyncio.wait_for(writer.drain(), timeout=0.2)
                    data = await asyncio.wait_for(reader.read(512), timeout=0.5)
                    writer.close()
                    await writer.wait_closed()
                    status_code = 200
                    status_str = "PASS"
                    is_crash = False
                    regs = None
                except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError) as e:
                    # Potential crash or reset
                    status_code = 500
                    status_str = "CRASH" if "Reset" in str(e) else "TIMEOUT"
                    is_crash = status_str == "CRASH"
                    regs = {"EXCEPTION": str(e), "STATUS": "CONNECTION_DROPPED"}
                latency_ms = (time.perf_counter() - case_start) * 1000.0

            # Register test case
            payload_repr = payload.decode(errors="replace").strip()
            if len(payload_repr) > 40:
                payload_repr = payload_repr[:37] + "..."

            test_cases.append(FuzzTestCase(
                case_id=case_idx,
                strategy=strat,
                payload_repr=payload_repr,
                payload_length=len(payload),
                response_code=status_code,
                response_latency_ms=round(latency_ms, 2),
                status=status_str
            ))

            # Record Crash Report
            if is_crash and regs:
                crash_repr = payload.decode(errors="replace")
                if len(crash_repr) > 50:
                    crash_repr = crash_repr[:47] + "..."
                
                # De-duplicate by strategy and crash register
                crashes.append(FuzzCrashReport(
                    case_id=case_idx,
                    strategy=strat,
                    payload_hex=payload.hex()[:64] + ("..." if len(payload) > 32 else ""),
                    payload_preview=crash_repr,
                    crash_reason=f"SIGSEGV / Abnormal termination on {strat} input vector.",
                    registers_snapshot=regs,
                    reproduction_command=f"python -c 'import socket; s=socket.socket(); s.connect((\"{req.target_host}\", {req.target_port})); s.send(bytes.fromhex(\"{payload.hex()}\"))'"
                ))

        total_duration = time.perf_counter() - start_time
        cps = round(total_cases / max(total_duration, 0.001), 1)

        # Deduplicate crashes by strategy
        unique_crashes = []
        seen_strats = set()
        for c in crashes:
            if c.strategy not in seen_strats:
                seen_strats.add(c.strategy)
                unique_crashes.append(c)

        return ProtocolFuzzResponse(
            target=f"{req.target_host}:{req.target_port}",
            total_cases_run=total_cases,
            cases_per_second=cps,
            crashes_detected=len(crashes),
            unique_crashes=unique_crashes,
            test_cases=test_cases[:50]  # Return sample of recent 50
        )

class WindowsACLAuditor:
    """
    Audits Windows Security Descriptor / Access Control Lists (ACL) JSON dumps
    to detect privilege escalation pathways and weak file permissions.
    """
    DANGEROUS_PERMISSIONS = {
        "FullControl", "GenericAll", "Write", "GenericWrite", "WriteData", "CreateFiles", "AppendData"
    }
    HIGH_RISK_PRINCIPALS = {
        "Everyone", "BUILTIN\\Users", "NT AUTHORITY\\Authenticated Users", "Users", "Authenticated Users"
    }

    @classmethod
    def audit_policy(cls, req: ACLAuditRequest) -> ACLAuditResponse:
        policy = req.policy_json
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except Exception as e:
                raise ValueError(f"Failed to parse JSON ACL document: {str(e)}")

        findings: List[ACLFinding] = []
        rules = policy.get("rules", []) if isinstance(policy, dict) else (policy if isinstance(policy, list) else [])

        for idx, rule in enumerate(rules):
            path = rule.get("path") or rule.get("Path") or f"Object_{idx}"
            principal = rule.get("principal") or rule.get("IdentityReference") or ""
            permission = rule.get("permission") or rule.get("FileSystemRights") or rule.get("Access") or ""
            access_control = rule.get("type") or rule.get("AccessControlType") or "Allow"

            if access_control.lower() != "allow":
                continue

            # Check if non-admin principal holds dangerous write/control permissions
            is_risky_principal = any(p.lower() in principal.lower() for p in cls.HIGH_RISK_PRINCIPALS)
            is_dangerous_perm = any(perm.lower() in permission.lower() for perm in cls.DANGEROUS_PERMISSIONS)

            if is_risky_principal and is_dangerous_perm:
                is_system_path = any(sys_dir in path.lower() for sys_dir in ["system32", "program files", "service", "windows"])
                risk = "CRITICAL" if is_system_path else "HIGH"
                desc = (
                    f"Unprivileged principal '{principal}' is granted '{permission}' on sensitive path '{path}'. "
                    f"Allows local attackers or malicious software to overwrite binary or DLL hijacking."
                )
                remed = f'icacls "{path}" /remove:g "{principal}"'

                findings.append(ACLFinding(
                    target_path=path,
                    principal=principal,
                    permission=permission,
                    risk_level=risk,
                    description=desc,
                    remediation_cmd=remed
                ))

        summary = (
            f"Audited {len(rules)} ACL entries. Identified {len(findings)} high-risk permission misconfigurations."
            if findings else "All evaluated Access Control Entries conform to least-privilege standards."
        )

        return ACLAuditResponse(
            total_rules_analyzed=len(rules),
            high_risk_findings=len(findings),
            findings=findings,
            compliance_summary=summary
        )

fuzz_engine = StatefulProtocolFuzzer()
acl_auditor = WindowsACLAuditor()

class StaticBinaryAuditor:
    """
    Parses ELF and PE binaries to audit compile-time security mitigations:
    - Stack Canary (__stack_chk_fail)
    - NX/DEP (PT_GNU_STACK execution flag or IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    - PIE / ASLR (ET_DYN or IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    - RELRO (PT_GNU_RELRO header)
    - Fortify Source (__*_chk)
    """

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        return calculate_shannon_entropy(data)

    @classmethod
    def audit_binary(cls, req: BinaryAuditRequest) -> BinaryAuditResponse:
        import os
        import base64

        data = b""
        safe_filename = os.path.basename(req.filename)

        if req.file_bytes_base64:
            data = base64.b64decode(req.file_bytes_base64)
        elif req.content_raw_hex:
            cleaned = req.content_raw_hex.replace("\\x", "").replace("0x", "")
            cleaned = "".join(cleaned.split())
            if len(cleaned) % 2 != 0:
                cleaned = "0" + cleaned
            data = bytes.fromhex(cleaned)
        else:
            candidate = settings.SAMPLE_ARTIFACTS_PATH / safe_filename
            if candidate.exists():
                with open(candidate, "rb") as f:
                    data = f.read()
            else:
                raise ValueError(f"Binary artifact '{safe_filename}' not found.")

        if len(data) < 16:
            raise ValueError("Binary payload is too small to contain valid executable headers.")

        # --- ELF Parsing ---
        if data.startswith(b"\x7fELF"):
            is_64 = data[4] == 2
            endian_char = "<" if data[5] == 1 else ">"
            endian_str = "Little Endian" if data[5] == 1 else "Big Endian"
            fmt_str = "ELF64" if is_64 else "ELF32"

            # e_type (2=ET_EXEC, 3=ET_DYN)
            e_type = struct.unpack_from(f"{endian_char}H", data, 16)[0]
            # e_machine (3=386, 62=x86_64, 40=ARM, 183=AArch64)
            e_machine = struct.unpack_from(f"{endian_char}H", data, 18)[0]
            arch_map = {3: "x86 (i386)", 62: "x86_64 (AMD64)", 40: "ARM", 183: "AArch64", 8: "MIPS"}
            arch_str = arch_map.get(e_machine, f"Machine({e_machine})")

            # e_entry
            entry_fmt = f"{endian_char}Q" if is_64 else f"{endian_char}I"
            e_entry = struct.unpack_from(entry_fmt, data, 24)[0]

            # Mitigations detection
            has_canary = b"__stack_chk_fail" in data
            has_fortify = b"_chk" in data
            is_pie = e_type == 3  # ET_DYN is Position Independent Executable

            # Program Headers for NX and RELRO
            e_phoff = struct.unpack_from(entry_fmt, data, 32)[0] if is_64 else struct.unpack_from(f"{endian_char}I", data, 28)[0]
            e_phentsize = struct.unpack_from(f"{endian_char}H", data, 54 if is_64 else 42)[0]
            e_phnum = struct.unpack_from(f"{endian_char}H", data, 56 if is_64 else 44)[0]

            nx_active = True  # Default assume NX unless PT_GNU_STACK has PF_X
            relro_status = "NONE"

            if 0 < e_phoff < len(data):
                for ph_idx in range(e_phnum):
                    ph_offset = e_phoff + (ph_idx * e_phentsize)
                    if ph_offset + 8 > len(data):
                        break
                    p_type = struct.unpack_from(f"{endian_char}I", data, ph_offset)[0]
                    # PT_GNU_STACK = 0x6474e551
                    if p_type == 0x6474e551:
                        # p_flags: offset 4 in ELF64, offset 24 in ELF32
                        flags_offset = ph_offset + (4 if is_64 else 24)
                        if flags_offset + 4 <= len(data):
                            p_flags = struct.unpack_from(f"{endian_char}I", data, flags_offset)[0]
                            # PF_X = 1
                            if p_flags & 1:
                                nx_active = False  # Executable stack!
                    # PT_GNU_RELRO = 0x6474e552
                    elif p_type == 0x6474e552:
                        relro_status = "PARTIAL"
                        if b"BIND_NOW" in data or b"\x18\x00\x00\x00" in data:
                            relro_status = "FULL"

            # Parse section hints
            sections: List[BinarySectionInfo] = []
            for sname in [b".text", b".data", b".rodata", b".bss"]:
                pos = data.find(sname)
                if pos != -1:
                    chunk = data[pos:pos + 128]
                    sections.append(BinarySectionInfo(
                        name=sname.decode(),
                        virtual_address=f"0x{0x400000 + pos:08x}",
                        raw_size=len(chunk),
                        entropy=cls._calculate_entropy(chunk),
                        flags="AX" if sname == b".text" else "WA"
                    ))

            if not sections:
                sections.append(BinarySectionInfo(
                    name=".text",
                    virtual_address=f"0x{e_entry:08x}",
                    raw_size=len(data),
                    entropy=cls._calculate_entropy(data),
                    flags="AX"
                ))

            # Security score calculation
            score = 0.0
            findings = []
            if has_canary:
                score += 2.5
            else:
                findings.append("Missing Stack Canary protection (-fno-stack-protector). Vulnerable to stack buffer overwrites.")

            if nx_active:
                score += 2.5
            else:
                findings.append("Stack marked EXECUTABLE (NX/DEP Disabled). Code execution directly on the stack is permitted.")

            if is_pie:
                score += 2.5
            else:
                findings.append("Position Independent Executable (PIE) disabled. Binary has a static, fixed base address.")

            if relro_status == "FULL":
                score += 2.5
            elif relro_status == "PARTIAL":
                score += 1.5
                findings.append("Partial RELRO enabled. Global Offset Table (GOT) is vulnerable to lazy binding overwrites.")
            else:
                findings.append("No RELRO protection. Global Offset Table (GOT) is writable.")

            verdict = "HARDENED" if score >= 8.0 else ("MODERATE_PROTECTION" if score >= 5.0 else "VULNERABLE_UNHARDENED")

            return BinaryAuditResponse(
                filename=safe_filename,
                binary_format=fmt_str,
                architecture=arch_str,
                endianness=endian_str,
                entry_point=f"0x{e_entry:08x}",
                mitigations=BinaryMitigations(
                    canary=has_canary,
                    nx_dep=nx_active,
                    pie_aslr=is_pie,
                    relro=relro_status,
                    fortify=has_fortify
                ),
                sections=sections,
                security_score=round(score, 1),
                verdict=verdict,
                findings=findings
            )

        # --- PE Parsing ---
        elif data.startswith(b"MZ"):
            pe_offset = struct.unpack_from("<I", data, 0x3c)[0] if len(data) >= 0x40 else 0
            if pe_offset + 24 <= len(data) and data[pe_offset:pe_offset+4] == b"PE\x00\x00":
                machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
                num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
                size_of_opt_header = struct.unpack_from("<H", data, pe_offset + 20)[0] if len(data) >= pe_offset + 22 else 0
                arch_str = "x86_64 (AMD64)" if machine == 0x8664 else ("x86 (I386)" if machine == 0x14c else f"PE-Machine({machine})")

                opt_header_offset = pe_offset + 24
                opt_magic = 0
                if size_of_opt_header >= 2 and opt_header_offset + 2 <= len(data):
                    opt_magic = struct.unpack_from("<H", data, opt_header_offset)[0]

                is_64 = (opt_magic == 0x20b) or (machine == 0x8664)
                fmt_str = "PE32+ (x64)" if is_64 else ("PE32 (x86)" if opt_magic == 0x10b else f"PE (Magic 0x{opt_magic:x})")

                # DllCharacteristics is at offset 70 for both standard PE32 and PE32+
                dll_char_offset = opt_header_offset + 70
                dll_char = 0
                if size_of_opt_header >= 72 and dll_char_offset + 2 <= len(data):
                    dll_char = struct.unpack_from("<H", data, dll_char_offset)[0]

                has_dep = bool(dll_char & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                has_aslr = bool(dll_char & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                has_cfg = bool(dll_char & 0x4000)   # IMAGE_DLLCHARACTERISTICS_GUARD_CF
                has_canary = b"__security_check_cookie" in data or b"@__security_check_cookie@" in data

                sections: List[BinarySectionInfo] = []
                for sname in [b".text", b".rdata", b".data"]:
                    pos = data.find(sname)
                    if pos != -1:
                        chunk = data[pos:pos + 128]
                        sections.append(BinarySectionInfo(
                            name=sname.decode(errors="ignore"),
                            virtual_address=f"0x{0x140001000 + pos:08x}",
                            raw_size=len(chunk),
                            entropy=cls._calculate_entropy(chunk),
                            flags="IMAGE_SCN_MEM_EXECUTE" if sname == b".text" else "IMAGE_SCN_MEM_READ"
                        ))

                if not sections:
                    sections.append(BinarySectionInfo(
                        name=".text",
                        virtual_address="0x140001000",
                        raw_size=len(data),
                        entropy=cls._calculate_entropy(data),
                        flags="IMAGE_SCN_MEM_EXECUTE"
                    ))

                score = 0.0
                findings = []
                if has_dep:
                    score += 3.0
                else:
                    findings.append("NX_COMPAT missing. Process does not enforce Data Execution Prevention (DEP).")

                if has_aslr:
                    score += 3.0
                else:
                    findings.append("DYNAMIC_BASE missing. Address Space Layout Randomization (ASLR) is disabled.")

                if has_canary:
                    score += 2.5
                else:
                    findings.append("Missing compiler security cookie (__security_check_cookie /GS).")

                if has_cfg:
                    score += 1.5

                verdict = "HARDENED" if score >= 8.0 else ("MODERATE_PROTECTION" if score >= 5.0 else "VULNERABLE_UNHARDENED")

                return BinaryAuditResponse(
                    filename=safe_filename,
                    binary_format=fmt_str,
                    architecture=arch_str,
                    endianness="Little Endian",
                    entry_point="0x140001000",
                    mitigations=BinaryMitigations(
                        canary=has_canary,
                        nx_dep=has_dep,
                        pie_aslr=has_aslr,
                        relro="FULL" if has_aslr else "NONE",
                        fortify=has_cfg
                    ),
                    sections=sections,
                    security_score=round(score, 1),
                    verdict=verdict,
                    findings=findings
                )

        raise ValueError(f"Unrecognized binary file format in '{safe_filename}'. Expected ELF or PE binary header.")

binary_auditor = StaticBinaryAuditor()

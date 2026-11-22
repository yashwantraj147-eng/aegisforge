import base64
import hashlib
import json
import math
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.app.core.config import settings
from backend.app.core.utils import calculate_shannon_entropy
from backend.app.core.logger import get_logger
from backend.app.models.schemas import (

logger = get_logger("mal_triage")
    TriageArtifactRequest, MalwareTriageResponse,
    EntropyBlock, YARAMatch, ATTACKTechnique
)

class MalwareTriageEngine:
    """
    Module 5: Static Binary Triage & Artifact Analysis Engine.
    Operates strictly on safe, benign synthetic artifacts or EICAR strings.
    Features:
      - Shannon entropy calculation (overall + sliding window block analysis)
      - Printable ASCII and UTF-16LE string extractor with categorization
      - Regex IOC (Indicators of Compromise) detector (IPs, URLs, emails, hashes)
      - YARA-style signature matcher evaluating default_yara_rules.json
      - MITRE ATT&CK matrix technique mapper
    """
    def __init__(self):
        self.rules = self._load_yara_rules()

    def _load_yara_rules(self) -> List[Dict[str, Any]]:
        rules_file = settings.RULES_PATH
        if rules_file.exists():
            try:
                with open(rules_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("rules", [])
            except Exception:
                pass
        return []

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Calculates Shannon entropy: H = -sum(p_i * log2(p_i)), range 0.0 to 8.0."""
        return calculate_shannon_entropy(data)

    def calculate_sliding_entropy(self, data: bytes, block_size: int = 256) -> List[EntropyBlock]:
        """Calculates entropy across sliding windows to pinpoint packed or encrypted sections."""
        blocks = []
        total = len(data)
        if total == 0:
            return blocks

        step = max(block_size // 2, 64)
        for offset in range(0, total, step):
            chunk = data[offset:offset + block_size]
            if len(chunk) < 32:
                continue
            e = self.calculate_shannon_entropy(chunk)
            blocks.append(EntropyBlock(
                offset=offset,
                size=len(chunk),
                entropy=round(e, 2)
            ))
        return blocks

    @staticmethod
    def extract_strings(data: bytes, min_len: int = 4) -> Dict[str, List[str]]:
        """Extracts and categorizes ASCII and UTF-16LE printable strings."""
        ascii_strings = [s.decode("latin-1", errors="ignore") for s in re.findall(rb"[ -~]{" + str(min_len).encode() + rb",}", data)]
        utf16_matches = re.findall(rb"(?:[ -~]\x00){" + str(min_len).encode() + rb",}", data) + \
                        re.findall(rb"(?:[ -~]\x00){" + str(min_len).encode() + rb",}", data[1:])
        utf16_strings = [u.decode("utf-16le", errors="ignore").strip("\x00 \t\r\n") for u in utf16_matches]
        all_strings = list(dict.fromkeys(ascii_strings + utf16_strings))

        categories: Dict[str, List[str]] = {
            "network": [],
            "filesystem": [],
            "apis": [],
            "commands": [],
            "general": []
        }

        api_keywords = {"VirtualAlloc", "CreateProcess", "CreateRemoteThread", "WriteProcessMemory",
                        "LoadLibrary", "GetProcAddress", "WSAStartup", "connect", "RegOpenKey"}
        cmd_keywords = {"cmd.exe", "powershell", "certutil", "-enc", "DownloadString", "Invoke-"}

        for s in all_strings:
            s_clean = s.strip()
            if any(proto in s_clean.lower() for proto in ["http://", "https://", "ftp://", "tcp://"]):
                categories["network"].append(s_clean)
            elif any(cmd.lower() in s_clean.lower() for cmd in cmd_keywords):
                categories["commands"].append(s_clean)
            elif any(api.lower() in s_clean.lower() for api in api_keywords):
                categories["apis"].append(s_clean)
            elif any(ext in s_clean.lower() for ext in [".exe", ".dll", ".sys", ".sh", "c:\\", "/usr/bin"]):
                categories["filesystem"].append(s_clean)
            else:
                if len(categories["general"]) < 50:
                    categories["general"].append(s_clean)

        return categories

    @staticmethod
    def extract_iocs(data: bytes) -> Dict[str, List[str]]:
        """Detects validated IPs, URLs, and emails inside raw payload."""
        text = data.decode("latin-1", errors="ignore")
        
        # Regex patterns
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        url_pattern = r"https?://[a-zA-Z0-9_\-\.]+(?::[0-9]+)?(?:/[^\s\"'<>]*)?"
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

        raw_ips = re.findall(ip_pattern, text)
        valid_ips = []
        for ip in set(raw_ips):
            try:
                parts = [int(p) for p in ip.split(".")]
                if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
                    valid_ips.append(ip)
            except ValueError:
                pass

        urls = list(set(re.findall(url_pattern, text)))
        emails = list(set(re.findall(email_pattern, text)))

        return {
            "ipv4_addresses": sorted(valid_ips),
            "urls": sorted(urls),
            "emails": sorted(emails)
        }

    def match_yara_rules(self, data: bytes, overall_entropy: float) -> List[YARAMatch]:
        """Evaluates loaded signatures against binary artifact bytes."""
        matches: List[YARAMatch] = []
        text = data.decode("latin-1", errors="ignore")
        hex_str = data.hex()

        for rule in self.rules:
            matched_items = []
            
            # Check entropy threshold
            if "min_entropy" in rule:
                if overall_entropy >= rule["min_entropy"]:
                    matched_items.append(f"Entropy {overall_entropy:.2f} >= {rule['min_entropy']}")

            # Check string signatures
            if "strings" in rule:
                target_strings = rule["strings"]
                found_strings = [s for s in target_strings if s in text]
                
                cond = rule.get("condition", "any_of")
                if cond == "any_of" and len(found_strings) > 0:
                    matched_items.extend(found_strings)
                elif cond == "all_of" and len(found_strings) == len(target_strings):
                    matched_items.extend(found_strings)
                elif cond == "at_least_n":
                    thresh = rule.get("threshold", 1)
                    if len(found_strings) >= thresh:
                        matched_items.extend(found_strings)

            # Check hex patterns
            if "hex_patterns" in rule:
                for pattern in rule["hex_patterns"]:
                    clean_pattern = pattern.replace(" ", "").lower()
                    if clean_pattern in hex_str:
                        matched_items.append(f"HexPattern({pattern})")

            if matched_items:
                matches.append(YARAMatch(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre_technique=rule.get("mitre_technique", "T1204"),
                    matched_strings=matched_items,
                    description=rule.get("description", "")
                ))

        return matches

    def map_mitre_attack(self, yara_matches: List[YARAMatch], iocs: Dict[str, List[str]], classified_strings: Dict[str, List[str]]) -> List[ATTACKTechnique]:
        """Maps discovered indicators and rule matches to MITRE ATT&CK matrix."""
        techniques: List[ATTACKTechnique] = []
        seen_ids = set()

        for m in yara_matches:
            if m.mitre_technique and "-" in m.mitre_technique:
                tech_id, tech_name = [p.strip() for p in m.mitre_technique.split("-", 1)]
                if tech_id not in seen_ids:
                    seen_ids.add(tech_id)
                    tactic = "Execution" if "1059" in tech_id or "1204" in tech_id else ("Defense Evasion" if "1027" in tech_id else "Privilege Escalation")
                    techniques.append(ATTACKTechnique(
                        id=tech_id,
                        name=tech_name,
                        tactic=tactic,
                        confidence="HIGH",
                        evidence=f"Matched YARA signature: {m.rule_name}"
                    ))

        # Add network C2 technique if URLs or IPs detected
        if (iocs.get("urls") or iocs.get("ipv4_addresses")) and "T1071" not in seen_ids:
            seen_ids.add("T1071")
            techniques.append(ATTACKTechnique(
                id="T1071",
                name="Application Layer Protocol",
                tactic="Command and Control",
                confidence="MEDIUM",
                evidence=f"Hardcoded network endpoints: {len(iocs.get('urls', []))} URLs, {len(iocs.get('ipv4_addresses', []))} IPs"
            ))

        return techniques

    def triage_artifact(self, req: TriageArtifactRequest) -> MalwareTriageResponse:
        import os
        safe_filename = os.path.basename(req.filename)

        # Decode data
        if req.file_bytes_base64:
            data = base64.b64decode(req.file_bytes_base64)
        elif req.content_raw_hex:
            cleaned = req.content_raw_hex.replace("\\x", "").replace("0x", "")
            cleaned = "".join(cleaned.split())
            if len(cleaned) % 2 != 0:
                cleaned = "0" + cleaned
            data = bytes.fromhex(cleaned)
        else:
            # Fallback to reading from sample artifacts if filename matches
            candidate = settings.SAMPLE_ARTIFACTS_PATH / safe_filename
            if candidate.exists():
                try:
                    with open(candidate, "rb") as f:
                        data = f.read()
                except (OSError, PermissionError):
                    if "eicar" in safe_filename.lower():
                        data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                    else:
                        data = safe_filename.encode("utf-8")
            else:
                if "eicar" in safe_filename.lower():
                    data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                else:
                    data = safe_filename.encode("utf-8")

        file_len = len(data)
        
        # Cryptographic Hashes
        hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }

        # Shannon Entropy
        overall_entropy = self.calculate_shannon_entropy(data)
        is_high_entropy = overall_entropy >= 7.2
        sliding_blocks = self.calculate_sliding_entropy(data)

        # File classification by magic bytes
        file_type = "Generic Binary Artifact"
        if data.startswith(b"\x7fELF"):
            file_type = "ELF Executable (Linux)"
        elif data.startswith(b"MZ"):
            file_type = "PE/COFF Executable (Windows)"
        elif b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
            file_type = "EICAR Antivirus Test Artifact"
        elif data.startswith(b"#!/"):
            file_type = "Shell Script Payload"

        # String & IOC extraction
        classified_strings = self.extract_strings(data)
        extracted_count = sum(len(v) for v in classified_strings.values())
        detected_iocs = self.extract_iocs(data)

        # YARA matching
        yara_matches = self.match_yara_rules(data, overall_entropy)

        # MITRE ATT&CK Mapping
        mitre_matrix = self.map_mitre_attack(yara_matches, detected_iocs, classified_strings)

        # Risk scoring
        risk_score = 0.0
        if "EICAR" in file_type:
            risk_score = 10.0
            verdict = "BENIGN_TEST_ARTIFACT (EICAR Indicator)"
        else:
            if is_high_entropy:
                risk_score += 3.5
            risk_score += min(len(yara_matches) * 2.5, 5.0)
            if detected_iocs["urls"]:
                risk_score += 1.5
            risk_score = min(round(risk_score, 1), 10.0)

            if risk_score >= 7.5:
                verdict = "SUSPICIOUS_HIGH_RISK"
            elif risk_score >= 4.0:
                verdict = "ANOMALOUS_HEURISTIC"
            else:
                verdict = "BENIGN_OR_CLEAN"

        return MalwareTriageResponse(
            filename=req.filename,
            file_size_bytes=file_len,
            file_type=file_type,
            hashes=hashes,
            overall_entropy=overall_entropy,
            is_high_entropy=is_high_entropy,
            entropy_sliding_window=sliding_blocks[:30],
            extracted_strings_count=extracted_count,
            classified_strings=classified_strings,
            detected_iocs=detected_iocs,
            yara_matches=yara_matches,
            mitre_attack_matrix=mitre_matrix,
            risk_score=risk_score,
            verdict=verdict
        )

malware_triage_engine = MalwareTriageEngine()

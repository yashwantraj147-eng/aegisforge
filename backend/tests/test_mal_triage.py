import pytest
from backend.app.engines.mal_triage import MalwareTriageEngine
from backend.app.models.schemas import TriageArtifactRequest

@pytest.fixture
def triage_engine():
    return MalwareTriageEngine()

def test_shannon_entropy_calculation(triage_engine):
    # Single repeated byte: entropy must be 0.0
    zero_entropy_data = b"A" * 1000
    assert triage_engine.calculate_shannon_entropy(zero_entropy_data) == 0.0

    # Uniform random distribution of bytes: entropy should be close to 8.0
    all_bytes = bytes(range(256)) * 4
    high_entropy = triage_engine.calculate_shannon_entropy(all_bytes)
    assert high_entropy >= 7.9

def test_printable_strings_and_iocs(triage_engine):
    mock_payload = (
        b"This is a benign test binary artifact.\n"
        b"Contact security admin at test-alert@aegisforge.internal.\n"
        b"Connecting to http://192.168.100.1:8080/c2_beacon...\n"
        b"Calls VirtualAllocEx and CreateRemoteThread for API test.\n"
    )
    req = TriageArtifactRequest(
        filename="test_mock.bin",
        file_bytes_base64=None,
        content_raw_hex=mock_payload.hex()
    )
    res = triage_engine.triage_artifact(req)

    assert res.extracted_strings_count > 0
    # Network string / URL check
    assert len(res.detected_iocs["urls"]) > 0
    assert any("http://192.168.100.1:8080" in u for u in res.detected_iocs["urls"])
    assert "192.168.100.1" in res.detected_iocs["ipv4_addresses"]
    assert "test-alert@aegisforge.internal" in res.detected_iocs["emails"]

def test_eicar_test_string_yara_detection(triage_engine):
    # Harmless standard EICAR string
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    req = TriageArtifactRequest(
        filename="eicar.com",
        content_raw_hex=eicar_bytes.hex()
    )
    res = triage_engine.triage_artifact(req)

    assert res.risk_score == 10.0
    assert "EICAR" in res.file_type
    # Must match RULE_001_EICAR_STANDARD
    matched_names = [m.rule_name for m in res.yara_matches]
    assert "EICAR_Standard_AV_Test_File" in matched_names

    # Check MITRE ATT&CK mapping
    attack_ids = [t.id for t in res.mitre_attack_matrix]
    assert "T1204" in attack_ids

def test_path_traversal_defense(triage_engine):
    # Attempt directory traversal filename
    req = TriageArtifactRequest(
        filename="../../../etc/shadow",
        content_raw_hex="90909090"
    )
    res = triage_engine.triage_artifact(req)
    assert res.filename == "../../../etc/shadow"
    assert res.file_size_bytes == 4

def test_utf16le_string_extraction(triage_engine):
    utf16_bytes = "VirtualAllocEx".encode("utf-16le") + b"\x00\x00" + "powershell.exe".encode("utf-16le")
    strings_map = triage_engine.extract_strings(utf16_bytes)
    assert any("VirtualAllocEx" in s for s in strings_map["apis"])
    assert any("powershell" in s for s in strings_map["commands"])

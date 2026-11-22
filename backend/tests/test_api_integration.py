import pytest

@pytest.mark.asyncio
async def test_health_endpoint(async_client):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "version" in data
    assert data["safety_guard_active"] is True

@pytest.mark.asyncio
async def test_recon_endpoints(async_client):
    # Port scan
    scan_res = await async_client.post("/api/v1/recon/scan", json={
        "target": "127.0.0.1",
        "start_port": 20,
        "end_port": 25,
        "timeout_ms": 100
    })
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["target"] == "127.0.0.1"

    # CVSS Calculator
    cvss_res = await async_client.post("/api/v1/recon/cvss", json={
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH"
    })
    assert cvss_res.status_code == 200
    cvss_data = cvss_res.json()
    assert cvss_data["base_score"] == 9.8
    assert cvss_data["severity"] == "CRITICAL"

    # CVD Report
    report_res = await async_client.post("/api/v1/recon/cvd-report", json={
        "title": "Stack Overflow in MiniProto Parser",
        "vulnerability_type": "CWE-121: Stack-based Buffer Overflow",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "target_component": "MiniProto Service v1.0",
        "remediation_guidance": "Implement length checks and stack canaries."
    })
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert "markdown_report" in report_data

@pytest.mark.asyncio
async def test_netarena_endpoints(async_client):
    # Status
    status_res = await async_client.get("/api/v1/netarena/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert len(status_data["nodes"]) == 3

    # Toggle MITM
    mitm_res = await async_client.post("/api/v1/netarena/mitm", json={"enable": True})
    assert mitm_res.status_code == 200
    assert mitm_res.json()["mitm_active"] is True

    # Toggle Active Defense
    defense_res = await async_client.post("/api/v1/netarena/defense", json={
        "enable": True,
        "enable_static_pinning": True,
        "enable_gratuitous_arp_counter": True
    })
    assert defense_res.status_code == 200
    assert defense_res.json()["active_defense_enabled"] is True

    # Packets
    packets_res = await async_client.get("/api/v1/netarena/packets?limit=5")
    assert packets_res.status_code == 200
    packets_data = packets_res.json()
    assert "packets" in packets_data

@pytest.mark.asyncio
async def test_exploit_studio_endpoints(async_client, sample_nop_sled_hex):
    # Shellcode analysis
    shell_res = await async_client.post("/api/v1/exploit/shellcode", json={
        "hex_payload": sample_nop_sled_hex,
        "architecture": "x86",
        "forbidden_bytes": ["00", "0a", "0d"]
    })
    assert shell_res.status_code == 200
    shell_data = shell_res.json()
    assert shell_data["has_nop_sled"] is True
    assert shell_data["null_byte_count"] == 0

    # Stack simulation
    stack_res = await async_client.post("/api/v1/exploit/stack-simulate", json={
        "buffer_allocated_bytes": 32,
        "input_payload_bytes": 48,
        "architecture": "x86_64",
        "enable_stack_canary": True,
        "enable_nx_dep": True,
        "enable_aslr": True,
        "enable_pie": True,
        "enable_relro": True,
        "hex_payload": sample_nop_sled_hex
    })
    assert stack_res.status_code == 200
    assert stack_res.json()["execution_verdict"] == "CANARY_TERMINATION"

@pytest.mark.asyncio
async def test_fuzz_re_endpoints(async_client):
    # Protocol Fuzzing
    fuzz_res = await async_client.post("/api/v1/fuzz/protocol", json={
        "target_host": "127.0.0.1",
        "target_port": 9999,
        "iteration_count": 10,
        "mutation_strategies": ["OVERSIZE_BUFFER", "FORMAT_STRING"]
    })
    assert fuzz_res.status_code == 200
    assert fuzz_res.json()["iterations_completed"] == 10

    # ACL Audit
    acl_res = await async_client.post("/api/v1/fuzz/acl-audit", json={
        "raw_json_policy": "{\"Path\": \"C:\\\\Test\", \"Owner\": \"SYSTEM\", \"Access\": [{\"Identity\": \"Everyone\", \"Rights\": \"FullControl\", \"Type\": \"Allow\"}]}"
    })
    assert acl_res.status_code == 200
    assert acl_res.json()["risk_verdict"] in ["HIGH_RISK_PERMISSIVE", "CRITICAL_INSECURE_PERMISSIONS"]

@pytest.mark.asyncio
async def test_maltriage_endpoints(async_client, sample_eicar_hex):
    # Analyze
    triage_res = await async_client.post("/api/v1/maltriage/analyze", json={
        "filename": "sample_eicar.com",
        "content_raw_hex": sample_eicar_hex
    })
    assert triage_res.status_code == 200
    triage_data = triage_res.json()
    assert len(triage_data["yara_matches"]) > 0

    # List Samples
    samples_res = await async_client.get("/api/v1/maltriage/samples")
    assert samples_res.status_code == 200
    assert "available_samples" in samples_res.json()

@pytest.mark.asyncio
async def test_scenarios_endpoints(async_client):
    # Run full scenario
    scen_res = await async_client.post("/api/v1/scenarios/run-purple-team")
    assert scen_res.status_code == 200
    data = scen_res.json()
    assert len(data["steps_executed"]) == 6
    assert data["final_verdict"] == "KILL_CHAIN_SUCCESSFULLY_NEUTRALIZED"

    # History
    hist_res = await async_client.get("/api/v1/scenarios/history")
    assert hist_res.status_code == 200
    assert isinstance(hist_res.json(), list)

@pytest.mark.asyncio
async def test_safety_guard_wan_rejection(async_client):
    # Attempting to scan WAN IP 8.8.8.8 should trigger a 400 safety guard violation
    res = await async_client.post("/api/v1/recon/scan", json={
        "target": "8.8.8.8",
        "start_port": 80,
        "end_port": 80
    })
    assert res.status_code == 400
    err = res.json()
    assert err["error"] == "SAFETY_GUARD_VIOLATION"

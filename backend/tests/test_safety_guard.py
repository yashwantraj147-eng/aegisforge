import pytest
from backend.app.core.safety_guard import SafetyGuard, SafetyViolationException

@pytest.fixture
def guard():
    return SafetyGuard()

def test_allowed_loopback_and_rfc1918(guard):
    # Loopback
    assert guard.is_ip_allowed("127.0.0.1") is True
    assert guard.is_ip_allowed("127.0.1.1") is True

    # Class A RFC1918
    assert guard.is_ip_allowed("10.0.0.1") is True
    assert guard.is_ip_allowed("10.254.1.50") is True

    # Class B RFC1918
    assert guard.is_ip_allowed("172.16.0.1") is True
    assert guard.is_ip_allowed("172.31.255.254") is True

    # Class C RFC1918
    assert guard.is_ip_allowed("192.168.1.1") is True
    assert guard.is_ip_allowed("192.168.100.105") is True

def test_blocked_public_wan_ips(guard):
    public_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "93.184.216.34", "104.244.42.1"]
    for ip in public_ips:
        assert guard.is_ip_allowed(ip) is False
        with pytest.raises(SafetyViolationException) as exc_info:
            guard.validate_target(ip)
        assert "SAFETY VIOLATION" in exc_info.value.message

def test_allowed_hostnames(guard):
    assert guard.is_hostname_allowed("localhost") is True
    assert guard.is_hostname_allowed("target.local") is True
    assert guard.is_hostname_allowed("node.internal") is True
    assert guard.is_hostname_allowed("gateway.aegis.internal") is True
    assert guard.is_hostname_allowed("mock.sandbox") is True

def test_blocked_public_domains(guard):
    blocked_domains = ["google.com", "github.com", "example.com", "aws.amazon.com", "cloudflare.com"]
    for domain in blocked_domains:
        assert guard.is_hostname_allowed(domain) is False
        with pytest.raises(SafetyViolationException) as exc_info:
            guard.validate_target(domain)
        assert "SAFETY VIOLATION" in exc_info.value.message

def test_cidr_validation(guard):
    # Allowed private CIDRs
    valid, _ = guard.validate_target("192.168.100.0/24")
    assert valid is True

    valid, _ = guard.validate_target("10.10.0.0/16")
    assert valid is True

    # Blocked public CIDR
    with pytest.raises(SafetyViolationException):
        guard.validate_target("8.8.8.0/24")

def test_uri_scheme_and_ipv6_sanitization(guard):
    # URI schemes should be stripped and target validated
    valid, _ = guard.validate_target("http://127.0.0.1:8000/api/v1")
    assert valid is True

    valid, _ = guard.validate_target("tcp://192.168.100.105:5000")
    assert valid is True

    # Bracketed IPv6
    valid, _ = guard.validate_target("[::1]:8080")
    assert valid is True

    # 0.0.0.0 local interfaces
    assert guard.is_ip_allowed("0.0.0.0") is True

def test_port_range_validation(guard):
    assert guard.validate_port_range(80, 443) is True
    assert guard.validate_port_range(1, 65535) is True

    with pytest.raises(ValueError):
        guard.validate_port_range(0, 100)
    with pytest.raises(ValueError):
        guard.validate_port_range(8080, 80)
    with pytest.raises(ValueError):
        guard.validate_port_range(100, 70000)

def test_blocked_suffix_spoofing(guard):
    # Domains that end with local or internal in name but are actually WAN domains
    spoofs = ["evil-local.com", "fakeinternal.net", "attacker-sandbox.org"]
    for s in spoofs:
        assert guard.is_hostname_allowed(s) is False
        with pytest.raises(SafetyViolationException):
            guard.validate_target(s)

def test_payload_size_validation(guard):
    # Normal payload within 1024 bytes
    normal_payload = "90" * 100
    assert guard.validate_payload_size(normal_payload, max_bytes=1024) is True

    # Oversized payload rejected
    oversized_payload = "41" * 3000
    with pytest.raises(SafetyViolationException) as exc_info:
        guard.validate_payload_size(oversized_payload, max_bytes=1024)
    assert "exceeds maximum sandbox limit" in str(exc_info.value.message)

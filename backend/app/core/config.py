from enum import Enum
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class ExecutionMode(str, Enum):
    SIMULATION = "SIMULATION"
    DOCKER_LIVE = "DOCKER_LIVE"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    PROJECT_NAME: str = "AegisForge Cyber Range & Vulnerability Workbench"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Dual Execution Mode (default SIMULATION for zero-privilege, portable execution)
    MODE: ExecutionMode = ExecutionMode.SIMULATION
    
    # Base directory paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    RULES_PATH: Path = BASE_DIR / "rules" / "default_yara_rules.json"
    SAMPLE_ARTIFACTS_PATH: Path = BASE_DIR.parent / "sandbox" / "sample_artifacts"
    
    # Safety guardrails
    ENFORCE_SAFETY_GUARD: bool = True
    MAX_PAYLOAD_BYTES: int = 1048576  # 1 MB max for hex payloads
    RATE_LIMIT_PER_MINUTE: int = 120

    # CORS allowlist (restricted to localhost development ports)
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    ALLOWED_NETWORKS: list[str] = [
        "127.0.0.0/8",      # Loopback
        "10.0.0.0/8",       # RFC 1918 Class A
        "172.16.0.0/12",    # RFC 1918 Class B
        "192.168.0.0/16",   # RFC 1918 Class C
        "169.254.0.0/16",   # IPv4 Link-Local
        "::1/128",          # IPv6 Loopback
        "fc00::/7",         # IPv6 ULA
        "fe80::/10"         # IPv6 Link-Local
    ]
    
    ALLOWED_HOSTNAMES: list[str] = [
        "localhost",
        "*.local",
        "*.lan",
        "*.internal",
        "*.test",
        "*.sandbox",
        "gateway.aegis.internal",
        "victim.aegis.internal",
        "monitor.aegis.internal"
    ]
    
    # Mock Targets in Sandbox
    GATEWAY_IP: str = "192.168.100.1"
    VICTIM_IP: str = "192.168.100.105"
    ATTACKER_IP: str = "192.168.100.200"
    


settings = Settings()

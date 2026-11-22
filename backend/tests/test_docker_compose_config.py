import re
from pathlib import Path
import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def test_root_docker_compose_validity():
    """Ensure root docker-compose.yml is valid YAML and adheres to architecture standards."""
    compose_path = ROOT_DIR / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist in repository root"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data
    services = compose_data["services"]

    # Verify all expected services are defined
    assert "backend" in services
    assert "frontend" in services
    assert "sandbox_gateway" in services
    assert "sandbox_victim" in services
    assert "sandbox_attacker" in services

    # Verify backend healthcheck and resource limits
    backend = services["backend"]
    assert "healthcheck" in backend
    assert "deploy" in backend and "resources" in backend["deploy"]
    assert backend["deploy"]["resources"]["limits"]["memory"] == "512M"
    assert "volumes" in backend

    # Verify frontend depends on healthy backend
    frontend = services["frontend"]
    assert "depends_on" in frontend
    assert frontend["depends_on"]["backend"]["condition"] == "service_healthy"
    assert "healthcheck" in frontend
    assert frontend["deploy"]["resources"]["limits"]["memory"] == "256M"

    # Verify isolated sandbox bridge network has internal: True
    networks = compose_data.get("networks", {})
    assert "aegis_sandbox_net" in networks
    assert networks["aegis_sandbox_net"].get("internal") is True
    subnet = networks["aegis_sandbox_net"]["ipam"]["config"][0]["subnet"]
    assert subnet == "192.168.100.0/24"


def test_sandbox_docker_compose_validity():
    """Ensure sandbox/docker-compose.sandbox.yml defines the 3-node micro-network securely."""
    sandbox_path = ROOT_DIR / "sandbox" / "docker-compose.sandbox.yml"
    assert sandbox_path.exists(), "sandbox/docker-compose.sandbox.yml must exist"

    with open(sandbox_path, "r", encoding="utf-8") as f:
        sandbox_data = yaml.safe_load(f)

    assert "services" in sandbox_data
    services = sandbox_data["services"]

    # Verify 3 distinct nodes
    assert "gateway" in services
    assert "victim" in services
    assert "monitor_attacker" in services

    # Verify IP addresses match the 192.168.100.0/24 schema
    gw_ip = services["gateway"]["networks"]["aegis_isolated_net"]["ipv4_address"]
    vic_ip = services["victim"]["networks"]["aegis_isolated_net"]["ipv4_address"]
    atk_ip = services["monitor_attacker"]["networks"]["aegis_isolated_net"]["ipv4_address"]

    assert gw_ip == "192.168.100.1"
    assert vic_ip == "192.168.100.105"
    assert atk_ip == "192.168.100.200"

    # Verify capabilities for packet interception and defense
    assert "NET_ADMIN" in services["gateway"]["cap_add"]
    assert "NET_ADMIN" in services["monitor_attacker"]["cap_add"]
    assert "NET_RAW" in services["monitor_attacker"]["cap_add"]

    # Verify strict internal isolation
    networks = sandbox_data.get("networks", {})
    assert networks["aegis_isolated_net"].get("internal") is True


def test_backend_dockerfile_multi_stage_and_security():
    """Verify backend Dockerfile uses multi-stage build, unprivileged user, and healthcheck."""
    dockerfile_path = ROOT_DIR / "backend" / "Dockerfile"
    assert dockerfile_path.exists()
    content = dockerfile_path.read_text(encoding="utf-8")

    # Multi-stage build check
    assert "FROM python:3.11-slim AS builder" in content
    assert "FROM python:3.11-slim AS runtime" in content

    # Non-root unprivileged security user check
    assert "groupadd -g 10001 aegis" in content
    assert "useradd -u 10001 -g aegis" in content
    assert "USER aegis" in content

    # Healthcheck & Expose check
    assert "HEALTHCHECK" in content
    assert "EXPOSE 8000" in content


def test_frontend_dockerfile_and_nginx_config():
    """Verify frontend Dockerfile multi-stage build and dedicated Nginx proxy configuration."""
    dockerfile_path = ROOT_DIR / "frontend" / "Dockerfile"
    nginx_path = ROOT_DIR / "frontend" / "nginx.conf"

    assert dockerfile_path.exists()
    assert nginx_path.exists()

    df_content = dockerfile_path.read_text(encoding="utf-8")
    assert "FROM node:20-alpine AS build" in df_content
    assert "FROM nginx:1.27-alpine AS runtime" in df_content
    assert "HEALTHCHECK" in df_content
    assert "EXPOSE 80" in df_content

    nginx_content = nginx_path.read_text(encoding="utf-8")
    # Verify security headers
    assert "X-Frame-Options" in nginx_content
    assert "X-Content-Type-Options" in nginx_content
    assert "Content-Security-Policy" in nginx_content

    # Verify WebSocket upgrade proxying
    assert "proxy_set_header Upgrade $http_upgrade;" in nginx_content
    assert 'proxy_set_header Connection "upgrade";' in nginx_content

    # Verify SPA fallback
    assert "try_files $uri $uri/ /index.html;" in nginx_content

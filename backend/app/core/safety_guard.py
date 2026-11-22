import ipaddress
import re
import socket
from typing import Tuple, Optional, Union
from urllib.parse import urlparse
from backend.app.core.config import settings

class SafetyViolationException(Exception):
    """Raised when an operation targets an unauthorized or public WAN destination."""
    def __init__(self, message: str, target: str):
        super().__init__(message)
        self.message = message
        self.target = target

class SafetyGuard:
    """
    Enforces strict RFC1918 and localhost allowlisting.
    Guarantees that all active scanning, packet replay, or socket connections
    are strictly isolated to internal virtual environments or loopback interfaces.
    Zero external internet/WAN probing is permitted.
    """
    
    def __init__(self):
        self.allowed_networks = [
            ipaddress.ip_network(net) for net in settings.ALLOWED_NETWORKS
        ]
        # Compiled patterns: strictly enforce subdomains ending with allowed suffixes
        self.allowed_patterns = []
        for h in settings.ALLOWED_HOSTNAMES:
            clean_h = h.strip().lower()
            if clean_h.startswith("*."):
                suffix = re.escape(clean_h[2:])
                # Matches single or multi-level subdomains: e.g. sub.node.local, gateway.aegis.internal
                pattern = re.compile(rf"^(?:[a-zA-Z0-9_\-]+\.)+{suffix}$", re.IGNORECASE)
            else:
                pattern = re.compile(rf"^{re.escape(clean_h)}$", re.IGNORECASE)
            self.allowed_patterns.append(pattern)

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Checks if an IPv4 or IPv6 string falls strictly within allowed internal subnets."""
        try:
            clean = ip_str.strip()
            # 0.0.0.0 represents all local interfaces (treated as loopback/local binding in sandbox)
            if clean in ["0.0.0.0", "::"]:
                return True

            ip_obj = ipaddress.ip_address(clean)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return any(ip_obj in net for net in self.allowed_networks)
            return False
        except ValueError:
            return False

    def is_hostname_allowed(self, hostname: str) -> bool:
        """Checks if a hostname complies with local sandbox domain patterns."""
        clean_host = hostname.strip().lower()
        if clean_host in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:
            return True
        return any(pattern.match(clean_host) for pattern in self.allowed_patterns)

    @staticmethod
    def sanitize_target_string(target: str) -> Tuple[str, Optional[int]]:
        """
        Strips URI schemes, URL paths, and extracts host and optional port.
        Examples:
          'http://127.0.0.1:8000/api' -> ('127.0.0.1', 8000)
          '[::1]:5000'               -> ('::1', 5000)
          'gateway.aegis.internal'   -> ('gateway.aegis.internal', None)
        """
        cleaned = target.strip()
        
        # Remove common protocol schemes
        for scheme in ["http://", "https://", "tcp://", "udp://", "ssh://", "ftp://", "ws://", "wss://"]:
            if cleaned.lower().startswith(scheme):
                cleaned = cleaned[len(scheme):]
                break

        # Remove query string if present
        if "?" in cleaned:
            cleaned = cleaned.split("?", 1)[0]

        # Remove path if present (unless it is a CIDR notation like 192.168.100.0/24)
        is_cidr = bool(re.match(r"^[0-9a-fA-F\.:]+/[0-9]{1,3}$", cleaned))
        if "/" in cleaned and not is_cidr:
            cleaned = cleaned.split("/", 1)[0]

        extracted_port = None

        # Check bracketed IPv6: e.g. [::1]:8000 or [::1]
        if cleaned.startswith("[") and "]" in cleaned:
            host_part = cleaned[1:cleaned.index("]")]
            remainder = cleaned[cleaned.index("]") + 1:]
            if remainder.startswith(":"):
                try:
                    extracted_port = int(remainder[1:])
                except ValueError:
                    pass
            return host_part, extracted_port

        # IPv4 or Hostname with port: e.g. 127.0.0.1:8000
        if ":" in cleaned and cleaned.count(":") == 1:
            parts = cleaned.split(":", 1)
            try:
                extracted_port = int(parts[1])
                return parts[0], extracted_port
            except ValueError:
                return cleaned, None

        return cleaned, None

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """
        Validates target IP, CIDR, or hostname.
        Raises SafetyViolationException if the target points to any public WAN endpoint.
        """
        if not settings.ENFORCE_SAFETY_GUARD:
            return True, "Safety guard disabled by configuration."

        if not target or not target.strip():
            raise SafetyViolationException("Target cannot be empty.", target=target)

        host_part, _ = self.sanitize_target_string(target)

        # Check CIDR notation
        if "/" in host_part:
            try:
                net_obj = ipaddress.ip_network(host_part, strict=False)
                if not (net_obj.is_private or net_obj.is_loopback or net_obj.is_link_local):
                    raise SafetyViolationException(
                        f"Target CIDR block '{target}' is NOT an RFC1918 private network. "
                        f"External WAN scanning is strictly blocked by AegisForge SafetyGuard.",
                        target=target
                    )
                for allowed in self.allowed_networks:
                    if net_obj.subnet_of(allowed):
                        return True, f"Target CIDR '{target}' validated within allowed sandbox network {allowed}."
                raise SafetyViolationException(
                    f"Target CIDR block '{target}' is not within designated laboratory subnets.",
                    target=target
                )
            except ValueError as e:
                raise SafetyViolationException(f"Invalid CIDR syntax: {str(e)}", target=target)

        # Check single IP
        try:
            ip_obj = ipaddress.ip_address(host_part)
            if self.is_ip_allowed(str(ip_obj)):
                return True, f"Target IP '{host_part}' is verified as an isolated RFC1918/localhost lab target."
            raise SafetyViolationException(
                f"SAFETY VIOLATION: IP '{host_part}' is a public WAN address. "
                f"AegisForge is strictly restricted to RFC1918 private subnets and localhost.",
                target=target
            )
        except ValueError:
            # Not an IP string, test hostname
            if self.is_hostname_allowed(host_part):
                # DNS verification: verify that hostname doesn't resolve to public WAN IP
                try:
                    resolved_addrs = socket.getaddrinfo(host_part, None)
                    for addr in resolved_addrs:
                        sockaddr = addr[4]
                        ip_resolved = sockaddr[0]
                        if not self.is_ip_allowed(ip_resolved):
                            raise SafetyViolationException(
                                f"SAFETY VIOLATION: Hostname '{host_part}' resolves to public WAN IP '{ip_resolved}'. Access denied.",
                                target=target
                            )
                except (socket.gaierror, OSError):
                    # Hostname not locally resolvable in simulation mode is acceptable if name matches sandbox pattern
                    pass

                return True, f"Target hostname '{host_part}' is verified as an allowed sandbox hostname."

            raise SafetyViolationException(
                f"SAFETY VIOLATION: Hostname '{host_part}' is not an authorized internal domain. "
                f"Allowed domains: localhost, *.local, *.lan, *.internal, *.test, *.sandbox.",
                target=target
            )

    def validate_port_range(self, start_port: int, end_port: int) -> bool:
        """Validates that scanned port ranges are within the legal TCP/UDP boundary 1-65535."""
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError(f"Port range ({start_port}-{end_port}) must be between 1 and 65535.")
        if start_port > end_port:
            raise ValueError(f"Start port ({start_port}) cannot be greater than end port ({end_port}).")

    def validate_payload_size(
        self,
        payload_data: Union[str, bytes],
        max_bytes: int = 1048576,
        field_name: str = "payload"
    ) -> bool:
        """
        Enforces upper size limit on payloads to prevent memory exhaustion / DoS.
        Hex string inputs are evaluated based on decoded byte length (len // 2).
        """
        if isinstance(payload_data, str):
            clean_hex = payload_data.replace(" ", "").replace("\\x", "").replace("0x", "")
            sz = len(clean_hex) // 2
        else:
            sz = len(payload_data)

        if sz > max_bytes:
            raise SafetyViolationException(
                f"SAFETY VIOLATION: Payload size ({sz} bytes) exceeds maximum sandbox limit of {max_bytes} bytes.",
                target=f"{field_name}:{sz}B"
            )
        return True
        return True

safety_guard = SafetyGuard()

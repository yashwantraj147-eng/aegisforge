import time
from datetime import datetime, timezone
from typing import Dict, Any

class TelemetryMetrics:
    """
    Central telemetry and operational counter service for AegisForge workbench.
    Provides standard JSON and Prometheus metrics exposition formats.
    """
    def __init__(self):
        self.boot_timestamp = time.time()
        self.total_requests = 0
        self.total_scans = 0
        self.total_open_ports_discovered = 0
        self.total_fuzz_cases_executed = 0
        self.total_crashes_detected = 0
        self.total_triages_executed = 0
        self.total_scenarios_executed = 0

    def record_request(self):
        self.total_requests += 1

    def record_scan(self, open_ports: int):
        self.total_scans += 1
        self.total_open_ports_discovered += open_ports

    def record_fuzz(self, cases: int, crashes: int):
        self.total_fuzz_cases_executed += cases
        self.total_crashes_detected += crashes

    def record_triage(self):
        self.total_triages_executed += 1

    def record_scenario(self):
        self.total_scenarios_executed += 1

    @property
    def uptime_seconds(self) -> float:
        return round(time.time() - self.boot_timestamp, 2)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "uptime_seconds": self.uptime_seconds,
            "started_at": datetime.fromtimestamp(self.boot_timestamp, tz=timezone.utc).isoformat(),
            "total_requests": self.total_requests,
            "scans_executed": self.total_scans,
            "open_ports_discovered": self.total_open_ports_discovered,
            "fuzz_cases_executed": self.total_fuzz_cases_executed,
            "crashes_detected": self.total_crashes_detected,
            "triages_executed": self.total_triages_executed,
            "scenarios_executed": self.total_scenarios_executed
        }

    def get_prometheus_format(self) -> str:
        lines = [
            "# HELP aegisforge_uptime_seconds Total runtime of AegisForge backend in seconds",
            "# TYPE aegisforge_uptime_seconds gauge",
            f"aegisforge_uptime_seconds {self.uptime_seconds}",
            "# HELP aegisforge_requests_total Total number of HTTP requests processed",
            "# TYPE aegisforge_requests_total counter",
            f"aegisforge_requests_total {self.total_requests}",
            "# HELP aegisforge_scans_total Total number of port reconnaissance scans executed",
            "# TYPE aegisforge_scans_total counter",
            f"aegisforge_scans_total {self.total_scans}",
            "# HELP aegisforge_fuzz_cases_total Total number of protocol fuzzing mutations tested",
            "# TYPE aegisforge_fuzz_cases_total counter",
            f"aegisforge_fuzz_cases_total {self.total_fuzz_cases_executed}",
            "# HELP aegisforge_crashes_total Total number of parser crash conditions detected",
            "# TYPE aegisforge_crashes_total counter",
            f"aegisforge_crashes_total {self.total_crashes_detected}",
            "# HELP aegisforge_triages_total Total number of binary artifacts triaged",
            "# TYPE aegisforge_triages_total counter",
            f"aegisforge_triages_total {self.total_triages_executed}",
            "# HELP aegisforge_scenarios_total Total number of Purple-Team end-to-end exercises completed",
            "# TYPE aegisforge_scenarios_total counter",
            f"aegisforge_scenarios_total {self.total_scenarios_executed}"
        ]
        return "\n".join(lines) + "\n"

metrics = TelemetryMetrics()

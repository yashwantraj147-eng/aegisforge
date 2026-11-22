import pytest
from backend.app.api.routes_scenarios import run_purple_team_exercise, get_scenario_history

@pytest.mark.asyncio
async def test_purple_team_orchestrator_scenario():
    """Validates the 6-stage Purple-Team Cyber Range orchestration end-to-end."""
    result = await run_purple_team_exercise()
    assert result.status == "COMPLETED"
    assert result.total_steps == 6
    assert len(result.steps) == 6

    # Check individual stage modules and statuses
    modules = [step.module for step in result.steps]
    assert modules == ["RECON", "NET_ARENA", "FUZZING", "EXPLOIT_STUDIO", "MAL_TRIAGE", "CVD"]

    # Verify telemetry metadata is populated for all steps
    for step in result.steps:
        assert step.status in ["SUCCESS", "MITIGATED"]
        assert step.telemetry is not None

    # Check scenario run history
    history = await get_scenario_history()
    assert len(history["runs"]) > 0
    assert any(r["scenario_id"] == result.scenario_id for r in history["runs"])

"""
Automated Integration Tests for Endpoints and Comparative Scenarios.
"""

from fastapi.testclient import TestClient
from app import app
from backend.routers.scenarios import SCENARIOS_CATALOG

client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_scenarios_endpoint():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) == len(SCENARIOS_CATALOG)
    assert any(s["id"] == "scenario_excessive_agency_idor" for s in scenarios)


def test_run_comparative_scenario_idor():
    response = client.post("/api/scenarios/run", json={
        "scenario_id": "scenario_excessive_agency_idor",
        "compare_mode": True
    })
    assert response.status_code == 200
    data = response.json()
    assert "baseline_run" in data
    assert "mitigated_run" in data
    assert data["baseline_run"]["security_decision"] == "ALLOWED"
    assert data["mitigated_run"]["security_decision"] == "BLOCKED"


def test_run_comparative_scenario_refund():
    response = client.post("/api/scenarios/run", json={
        "scenario_id": "scenario_excessive_agency_refund",
        "compare_mode": True
    })
    assert response.status_code == 200
    data = response.json()
    assert data["baseline_run"]["security_decision"] == "ALLOWED"
    assert data["mitigated_run"]["security_decision"] in ["BLOCKED", "PENDING_APPROVAL"]


def test_security_config_endpoints():
    # Test getting config
    res_get = client.get("/api/security/config")
    assert res_get.status_code == 200
    config = res_get.json()
    assert "rbac_enabled" in config

    # Test baseline preset
    res_base = client.post("/api/security/preset/baseline")
    assert res_base.status_code == 200
    assert res_base.json()["config"]["rbac_enabled"] is False

    # Test hardened preset
    res_hard = client.post("/api/security/preset/hardened")
    assert res_hard.status_code == 200
    assert res_hard.json()["config"]["rbac_enabled"] is True

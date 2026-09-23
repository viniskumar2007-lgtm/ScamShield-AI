from fastapi.testclient import TestClient
from main import app


def test_validation_and_request_id():
    with TestClient(app) as client:
        response = client.post("/api/analyze", json={"message": ""})
        assert response.status_code == 422
        assert "success" in response.json()
        assert response.headers.get("X-Request-ID")


def test_cors_is_not_wildcard():
    with TestClient(app) as client:
        response = client.options("/api/analyze", headers={
            "Origin": "https://untrusted.invalid",
            "Access-Control-Request-Method": "POST",
        })
        assert response.headers.get("access-control-allow-origin") != "*"


def test_history_requires_identity():
    with TestClient(app) as client:
        assert client.get("/api/history").status_code == 503

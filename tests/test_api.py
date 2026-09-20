import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

import llm_client  # noqa: E402
import main  # noqa: E402
from hide_engine import hide_variation_selector  # noqa: E402

KEY = {"X-API-Key": "demo-key-12345"}
COVER = "Sure, here is a quick summary of today's meeting notes for the team."


@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:  # runs lifespan -> init_db + seeds demo key
        yield c


def test_health_and_metrics(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").status_code == 200
    assert client.get("/metrics").status_code == 200


def test_catch_blocks_glassworm_payload(client):
    r = client.post("/api/catch", json={"text": hide_variation_selector("api_key=sk-1", COVER)}, headers=KEY)
    assert r.status_code == 200 and r.json()["action"] == "BLOCK"
    assert r.headers["X-Request-ID"] and r.headers["X-Content-Type-Options"] == "nosniff"


def test_catch_allows_emoji_reply(client):
    r = client.post("/api/catch", json={"text": "All done ✅ thanks ❤️"}, headers=KEY)
    assert r.json()["action"] == "ALLOW"


def test_auth_required_and_admin_gate(client):
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/admin/keys").status_code == 401


def test_oversized_input_rejected(client):
    r = client.post("/api/catch", json={"text": "a" * (main.MAX_TEXT_CHARS + 1)}, headers=KEY)
    assert r.status_code == 422


def test_audit_chain_verifies_over_api(client):
    client.post("/api/catch", json={"text": "hello world"}, headers=KEY)
    assert client.get("/api/audit/verify", headers=KEY).json()["valid"] is True


def test_openai_compatible_gateway_withholds_attack(client, monkeypatch):
    async def fake_upstream(payload):
        return {"choices": [{"index": 0, "finish_reason": "stop", "message": {
            "role": "assistant", "content": hide_variation_selector("api_key=sk-1", COVER)}}]}
    monkeypatch.setattr(llm_client, "chat_completion", fake_upstream)
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer demo-key-12345"},
                    json={"messages": [{"role": "user", "content": "hi"}]})
    body = r.json()
    assert r.status_code == 200 and body["exfilwatch"]["withheld"] is True
    assert body["choices"][0]["finish_reason"] == "content_filter"

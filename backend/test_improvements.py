from services.risk_engine import calculate_hybrid_score
from services.rule_engine import calculate_rule_score
from services.url_analyzer import analyze_url


def test_rule_matching_uses_word_boundaries():
    result = calculate_rule_score("The system is urgenting a maintenance task.")
    assert "urgent" not in result["matched_keywords"]


def test_fallback_score_mode_uses_rule_weight():
    result = calculate_hybrid_score(
        {"rule_score": 80},
        {"ai_risk_score": 100, "score_mode": "FALLBACK"},
    )
    assert result["score_mode"] == "RULE_FALLBACK"
    assert result["risk_score"] == 83


def test_official_https_brand_domain_is_not_flagged_as_impersonation():
    result = analyze_url("https://www.google.com")
    assert result["score"] == 0
    assert result["is_suspicious"] is False


def test_brand_lookalike_domain_is_flagged():
    result = analyze_url("https://google.com.evil.example/login")
    assert any(
        item["indicator"] == "Possible brand impersonation"
        for item in result["indicators"]
    )


def test_url_with_whitespace_is_rejected():
    result = analyze_url("not a url")
    assert result["domain"] == ""
    assert result["indicators"][0]["indicator"] == "Invalid URL"

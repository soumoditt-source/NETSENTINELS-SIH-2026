from __future__ import annotations

from unittest.mock import patch

from addons.netsentinel_plus.providers import ProviderService


def test_private_ioc_is_rejected_without_provider_call():
    service = ProviderService()
    service.keys = {provider: "key" for provider in service.keys}
    with patch.object(service, "_request") as request:
        result = service.lookup(ip="10.0.0.7")
    request.assert_not_called()
    assert result["status"] == "rejected"
    assert result["targets"] == []
    assert result["rejected"][0]["kind"] == "ip"


def test_missing_keys_degrade_to_offline_metadata_result():
    service = ProviderService()
    service.keys = {provider: "" for provider in service.keys}
    result = service.lookup(ip="8.8.8.8", domain="example.org")
    assert result["status"] == "offline"
    assert result["metadata_only"] is True
    assert result["detector_score_unchanged"] is True
    assert result["results"] == []


def test_cached_provider_result_is_reused():
    service = ProviderService()
    service.keys = {provider: "" for provider in service.keys}
    service.keys["abuseipdb"] = "key"
    calls = 0

    def fake_request(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {"data": {"abuseConfidenceScore": 12, "totalReports": 1}}

    with patch.object(service, "_request", side_effect=fake_request):
        first = service.lookup(ip="8.8.8.8")
        second = service.lookup(ip="8.8.8.8")

    assert calls == 1
    assert first["results"][0]["status"] == "ok"
    assert second["results"][0]["cached"] is True


def test_mistral_brief_prompt_excludes_network_identity():
    service = ProviderService()
    service.keys = {provider: "" for provider in service.keys}
    service.keys["mistral"] = "key"
    captured = {}

    def fake_request(provider, url, **kwargs):
        captured["body"] = kwargs["body"]
        return {"choices": [{"message": {"content": "Assessment\nMetadata is suspicious."}}]}

    alert = {
        "source_ip": "8.8.8.8",
        "threat_class": "C2 Beacon",
        "confidence": 0.91,
        "supporting_evidence": ["regular interval"],
        "feature_snapshot": {"inter_arrival_cv": 0.02},
    }
    with patch.object(service, "_request", side_effect=fake_request):
        result = service.brief(
            alert,
            {
                "targets": [{"kind": "ip", "value": "8.8.8.8"}],
                "results": [{"provider": "threatfox", "target": {"kind": "ip", "value": "8.8.8.8"}, "iocs": [{"ioc": "8.8.8.8"}]}],
            },
        )

    assert result["status"] == "completed"
    serialized = captured["body"]["messages"][1]["content"]
    assert "8.8.8.8" not in serialized
    assert "C2 Beacon" in serialized

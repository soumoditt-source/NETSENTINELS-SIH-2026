"""Safe optional provider clients for the NetSentinel Plus sidecar.

The provider layer accepts only public IPs, domains, and SHA-256 values. It
does not accept files, download samples, execute content, or alter detector
scores. All providers are optional and cache-backed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


class ProviderService:
    """Cache-backed, metadata-only enrichment for analyst review."""

    def __init__(self) -> None:
        self.keys = {
            "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
            "threatfox": os.getenv("THREATFOX_AUTH_KEY", "").strip(),
            "virustotal": os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
            "urlhaus": os.getenv("URLHAUS_AUTH_KEY", "").strip(),
            "mistral": os.getenv("MISTRAL_API_KEY", "").strip(),
        }
        self.mistral_model = os.getenv("MISTRAL_MODEL", "mistral-small-latest").strip() or "mistral-small-latest"
        self.backend_url = os.getenv("NETSENTINEL_BACKEND_URL", "http://127.0.0.1:8100").rstrip("/")
        self.timeout = max(1.0, min(float(os.getenv("NETSENTINEL_INTEL_TIMEOUT_S", "4")), 15.0))
        self.cache_ttl = max(60, int(os.getenv("NETSENTINEL_INTEL_CACHE_TTL_S", "900")))
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def status(self) -> dict[str, Any]:
        configured = {provider: bool(key) for provider, key in self.keys.items()}
        return {
            "mode": "additive_metadata_enrichment",
            "configured_providers": configured,
            "active_provider_count": sum(configured.values()),
            "metadata_only": True,
            "payload_downloads": False,
            "private_network_lookups": False,
            "detector_scores_changed": False,
            "mistral_model": self.mistral_model if configured["mistral"] else None,
            "cache_ttl_seconds": self.cache_ttl,
        }

    def lookup(self, *, ip: str | None = None, domain: str | None = None, sha256: str | None = None) -> dict[str, Any]:
        targets: list[dict[str, str]] = []
        rejected: list[dict[str, str]] = []
        if ip:
            normalized = self._public_ip(ip)
            if normalized:
                targets.append({"kind": "ip", "value": normalized})
            else:
                rejected.append({"kind": "ip", "reason": "Only public IP addresses are eligible."})
        if domain:
            normalized = self._domain(domain)
            if normalized:
                targets.append({"kind": "domain", "value": normalized})
            else:
                rejected.append({"kind": "domain", "reason": "Only a valid external domain is eligible."})
        if sha256:
            normalized = sha256.strip().lower()
            if SHA256_PATTERN.fullmatch(normalized):
                targets.append({"kind": "sha256", "value": normalized})
            else:
                rejected.append({"kind": "sha256", "reason": "Only a SHA-256 digest is eligible."})

        results: list[dict[str, Any]] = []
        for target in targets:
            if self.keys["abuseipdb"] and target["kind"] == "ip":
                results.append(self._cached("abuseipdb", target, self._abuseipdb))
            if self.keys["threatfox"]:
                results.append(self._cached("threatfox", target, self._threatfox))
            if self.keys["virustotal"]:
                results.append(self._cached("virustotal", target, self._virustotal))
            if self.keys["urlhaus"] and target["kind"] == "domain":
                results.append(self._cached("urlhaus", target, self._urlhaus))
        state = "rejected" if rejected and not targets else "no_ioc" if not targets else "offline"
        if any(result.get("status") == "ok" for result in results):
            state = "completed"
        return {
            "status": state,
            "targets": targets,
            "rejected": rejected,
            "results": results,
            "metadata_only": True,
            "detector_score_unchanged": True,
            "generated_at": time.time(),
        }

    def brief(self, alert: dict[str, Any], intelligence: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.keys["mistral"]:
            return {
                "status": "not_configured",
                "provider": "mistral",
                "message": "Set MISTRAL_API_KEY locally to enable analyst briefs.",
            }
        safe_alert = {
            "threat_class": alert.get("threat_class"),
            "severity": alert.get("severity"),
            "confidence": alert.get("confidence"),
            "risk_score": alert.get("risk_score"),
            "detector": alert.get("detector"),
            "detector_method": alert.get("detector_method"),
            "supporting_evidence": (alert.get("supporting_evidence") or [])[:8],
            "feature_snapshot": _compact_features(alert.get("feature_snapshot") or {}),
            "mitre": alert.get("mitre") or alert.get("mitre_attack_mapping") or {},
            "external_intelligence": _redact_intelligence(intelligence or alert.get("external_intelligence") or {}),
            "read_only": True,
            "payload_decrypted": False,
        }
        body = {
            "model": self.mistral_model,
            "temperature": 0.1,
            "max_tokens": 350,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a defensive network-forensics analyst. Summarize only supplied metadata. Do not invent indicators, claim certainty, advise execution, or recommend blocking. Use headings Assessment, Evidence, Safe next step.",
                },
                {"role": "user", "content": json.dumps(safe_alert, separators=(",", ":"))},
            ],
        }
        try:
            response = self._request("mistral", "https://api.mistral.ai/v1/chat/completions", method="POST", headers={"Authorization": f"Bearer {self.keys['mistral']}"}, body=body)
            choices = response.get("choices") or []
            content = ((choices[0].get("message") or {}).get("content") if choices else "")
            if not isinstance(content, str) or not content.strip():
                return {"status": "empty", "provider": "mistral"}
            return {"status": "completed", "provider": "mistral", "model": self.mistral_model, "brief": content.strip()[:6000], "generated_at": time.time()}
        except Exception as exc:
            return {"status": "unavailable", "provider": "mistral", "message": _safe_error(exc)}

    def _cached(self, provider: str, target: dict[str, str], handler: Callable[[dict[str, str]], dict[str, Any]]) -> dict[str, Any]:
        key = f"{provider}:{target['kind']}:{target['value']}"
        now = time.time()
        with self._lock:
            entry = self._cache.get(key)
            if entry and now - entry[0] < self.cache_ttl:
                result = dict(entry[1])
                result["cached"] = True
                result["cache_age_seconds"] = round(now - entry[0], 1)
                return result
        try:
            result = handler(target)
        except Exception as exc:
            result = {"provider": provider, "target": target, "status": "unavailable", "message": _safe_error(exc), "cached": False}
        result.setdefault("provider", provider)
        result.setdefault("target", target)
        result.setdefault("cached", False)
        with self._lock:
            self._cache[key] = (time.time(), result)
        return result

    def _abuseipdb(self, target: dict[str, str]) -> dict[str, Any]:
        query = urlencode({"ipAddress": target["value"], "maxAgeInDays": "90"})
        payload = self._request("abuseipdb", f"https://api.abuseipdb.com/api/v2/check?{query}", headers={"Key": self.keys["abuseipdb"], "Accept": "application/json"})
        data = payload.get("data") or {}
        return {"provider": "abuseipdb", "target": target, "status": "ok", "abuse_confidence_score": data.get("abuseConfidenceScore"), "total_reports": data.get("totalReports"), "last_reported_at": data.get("lastReportedAt"), "country_code": data.get("countryCode"), "usage_type": data.get("usageType"), "cached": False}

    def _threatfox(self, target: dict[str, str]) -> dict[str, Any]:
        payload = self._request("threatfox", "https://threatfox-api.abuse.ch/api/v1/", method="POST", headers={"Auth-Key": self.keys["threatfox"]}, body={"query": "search_ioc", "search_term": target["value"]})
        rows = payload.get("data") if isinstance(payload.get("data"), list) else []
        return {"provider": "threatfox", "target": target, "status": "ok", "ioc_count": len(rows), "iocs": [{"ioc": row.get("ioc"), "threat_type": row.get("threat_type"), "malware": row.get("malware_printable") or row.get("malware"), "confidence_level": row.get("confidence_level"), "last_seen": row.get("last_seen")} for row in rows[:5]], "cached": False}

    def _virustotal(self, target: dict[str, str]) -> dict[str, Any]:
        endpoints = {"ip": "ip_addresses", "domain": "domains", "sha256": "files"}
        endpoint = f"https://www.virustotal.com/api/v3/{endpoints[target['kind']]}/{target['value']}"
        payload = self._request("virustotal", endpoint, headers={"x-apikey": self.keys["virustotal"]})
        attributes = ((payload.get("data") or {}).get("attributes") or {})
        return {"provider": "virustotal", "target": target, "status": "ok", "reputation": attributes.get("reputation"), "last_analysis_stats": attributes.get("last_analysis_stats", {}), "tags": (attributes.get("tags") or [])[:10], "cached": False}

    def _urlhaus(self, target: dict[str, str]) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.keys["urlhaus"]:
            headers["Auth-Key"] = self.keys["urlhaus"]
        payload = self._request("urlhaus", "https://urlhaus-api.abuse.ch/v1/host/", method="POST", headers=headers, form={"host": target["value"]})
        return {"provider": "urlhaus", "target": target, "status": "ok", "url_count": payload.get("url_count", 0), "blacklists": payload.get("blacklists", {}), "query_status": payload.get("query_status"), "cached": False}

    def _request(self, provider: str, url: str, *, method: str = "GET", headers: dict[str, str] | None = None, body: dict[str, Any] | None = None, form: dict[str, str] | None = None) -> dict[str, Any]:
        request_headers = {"User-Agent": "NetSentinel-Plus/1.0 metadata-only"}
        request_headers.update(headers or {})
        data = None
        if body is not None:
            request_headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        elif form is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urlencode(form).encode("utf-8")
        try:
            with urlopen(Request(url, data=data, headers=request_headers, method=method), timeout=self.timeout) as response:
                raw = response.read(512 * 1024)
        except HTTPError as exc:
            raise RuntimeError(f"{provider} returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"{provider} network unavailable") from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"{provider} returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"{provider} returned unsupported data")
        return payload

    @staticmethod
    def _public_ip(value: str) -> str | None:
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        return str(address) if address.is_global else None

    @staticmethod
    def _domain(value: str) -> str | None:
        normalized = value.strip().lower().rstrip(".")
        if not DOMAIN_PATTERN.fullmatch(normalized):
            return None
        return normalized


def _compact_features(features: dict[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in list(features.items())[:32] if isinstance(value, (str, int, float, bool)) or value is None}


def _redact_intelligence(intelligence: dict[str, Any]) -> dict[str, Any]:
    """Remove raw IOC values before evidence is sent to a language model."""

    redacted: dict[str, Any] = {}
    for key, value in intelligence.items():
        if key == "targets" and isinstance(value, list):
            redacted[key] = [
                {"kind": item.get("kind"), "fingerprint": stable_fingerprint(str(item.get("value", "")))}
                for item in value
                if isinstance(item, dict)
            ]
        elif key == "results" and isinstance(value, list):
            redacted[key] = [_redact_intelligence_item(item) for item in value if isinstance(item, dict)]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            redacted[key] = value
    return redacted


def _redact_intelligence_item(item: dict[str, Any]) -> dict[str, Any]:
    redacted = {}
    for key, value in item.items():
        if key == "target" and isinstance(value, dict):
            redacted[key] = {"kind": value.get("kind"), "fingerprint": stable_fingerprint(str(value.get("value", "")))}
        elif isinstance(value, (str, int, float, bool)) or value is None:
            redacted[key] = value
        elif key == "iocs" and isinstance(value, list):
            redacted[key] = [{ioc_key: ioc_value for ioc_key, ioc_value in ioc.items() if ioc_key != "ioc"} for ioc in value if isinstance(ioc, dict)]
    return redacted


def _safe_error(error: Exception) -> str:
    return str(error).replace("\n", " ").strip()[:240] or "Provider unavailable"


def stable_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

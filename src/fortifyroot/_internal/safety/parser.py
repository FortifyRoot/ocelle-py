"""Tolerant parser for backend SDK config payloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fortifyroot._internal.safety.models import (
    ConfigProfile,
    RegexMatcher,
    SafetyConfig,
    SafetyRule,
    SdkConfigResponse,
    StringListMatcher,
    UdfMatcher,
)

_VALID_CATEGORIES = {
    "PII",
    "PCI",
    "PHI",
    "API_KEY",
    "SECRET",
    "PROMPT_INJECTION",
    "PROFANITY",
    "TOXICITY",
    "VIOLENCE",
    "SELF_HARM",
    "CONFIDENTIAL",
    "CUSTOM",
}


def parse_sdk_config_response(payload: Mapping[str, Any]) -> SdkConfigResponse:
    not_modified = bool(_get_value(payload, "notModified", "not_modified", default=False))
    profile_payload = _get_value(payload, "configProfile", "config_profile")
    profile = parse_config_profile(profile_payload) if isinstance(profile_payload, Mapping) else None
    return SdkConfigResponse(config_profile=profile, not_modified=not_modified)


def parse_config_profile(payload: Mapping[str, Any]) -> ConfigProfile:
    config_payload = _as_mapping(_get_value(payload, "config", default={}))
    safety_payload = _as_mapping(
        _get_value(config_payload, "safetyConfig", "safety_config", default={})
    )
    return ConfigProfile(
        config_profile_id=str(
            _get_value(payload, "id", "configProfileId", "config_profile_id", default="")
        ),
        version=_to_int(_get_value(payload, "version", default=0)),
        etag=str(_get_value(payload, "etag", default="")),
        safety=parse_safety_config(safety_payload),
    )


def parse_safety_config(payload: Mapping[str, Any]) -> SafetyConfig:
    rules = []
    for rule_payload in _get_value(payload, "rules", default=()) or ():
        if not isinstance(rule_payload, Mapping):
            continue
        rule = parse_safety_rule(rule_payload)
        if rule is not None:
            rules.append(rule)

    return SafetyConfig(
        enabled=bool(_get_value(payload, "enabled", default=False)),
        default_action=_normalize_action(
            _get_value(payload, "defaultAction", "default_action", default="ALLOW")
        ),
        rules=tuple(rules),
    )


def parse_safety_rule(payload: Mapping[str, Any]) -> SafetyRule | None:
    name = _to_optional_str(_get_value(payload, "name"))
    category = _normalize_category(_get_value(payload, "category"))
    if not name or not category:
        return None

    raw_action = _get_value(payload, "action")
    action = _normalize_optional_action(raw_action)
    if raw_action is not None and action is None:
        return None

    matcher = _parse_matcher(payload)
    if matcher is None:
        return None

    return SafetyRule(
        name=name,
        category=category,
        severity=_normalize_severity(_get_value(payload, "severity")),
        action=action,
        enabled=bool(_get_value(payload, "enabled", default=False)),
        matcher=matcher,
    )


def _parse_matcher(payload: Mapping[str, Any]):
    regex = _to_optional_str(_get_value(payload, "regex"))
    if regex:
        return RegexMatcher(pattern=regex)

    list_payload = _as_mapping(_get_value(payload, "list", default={}))
    if not list_payload:
        list_payload = _as_mapping(_get_value(payload, "listMatcher", "list_matcher", default={}))
    values = tuple(
        dict.fromkeys(
            value
            for value in (_get_value(list_payload, "values", default=()) or ())
            if isinstance(value, str)
        )
    )
    if values:
        return StringListMatcher(
            values=values,
            ignore_case=bool(_get_value(list_payload, "ignoreCase", "ignore_case", default=False)),
        )

    udf_payload = _as_mapping(_get_value(payload, "udf", default={}))
    if not udf_payload:
        udf_payload = _as_mapping(_get_value(payload, "udfMatcher", "udf_matcher", default={}))
    entry_point = _to_optional_str(_get_value(udf_payload, "entryPoint", "entry_point"))
    if entry_point:
        languages = tuple(
            language
            for language in (
                _normalize_language(raw)
                for raw in (_get_value(udf_payload, "languages", default=()) or ())
            )
            if language is not None
        )
        return UdfMatcher(entry_point=entry_point, languages=languages)

    return None


def _get_value(payload: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in payload:
            return payload[name]
    return default


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _to_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _to_optional_str(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def _normalize_category(value: Any) -> str | None:
    normalized = _normalize_enum(value, "SAFETY_CATEGORY_")
    if normalized in _VALID_CATEGORIES:
        return normalized
    return None


def _normalize_severity(value: Any) -> str:
    normalized = _normalize_enum(value, "SEVERITY_")
    if normalized in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return normalized
    return "MEDIUM"


def _normalize_action(value: Any) -> str:
    normalized = _normalize_enum(value, "SAFETY_ACTION_")
    if normalized in {"ALLOW", "MASK"}:
        return normalized
    return "ALLOW"


def _normalize_optional_action(value: Any) -> str | None:
    if value is None:
        return None
    normalized = _normalize_enum(value, "SAFETY_ACTION_")
    if normalized in {"ALLOW", "MASK"}:
        return normalized
    return None


def _normalize_language(value: Any) -> str | None:
    normalized = _normalize_enum(value, "SDK_LANGUAGE_")
    if normalized in {"PYTHON", "TYPESCRIPT", "GO"}:
        return normalized
    return None


def _normalize_enum(value: Any, prefix: str) -> str | None:
    if isinstance(value, str):
        normalized = value.strip().upper().replace("-", "_")
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
        return normalized or None
    if isinstance(value, int):
        return str(value)
    return None

"""Compiled text safety engine."""

from __future__ import annotations

import importlib
import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from opentelemetry.metrics import get_meter

from fortifyroot._internal.safety.models import (
    ConfigProfile,
    RegexMatcher,
    SafetyRule,
    StringListMatcher,
    UdfMatcher,
)
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyDecision,
    SafetyFinding,
    SafetyResult,
)
from fortifyroot.safety import TextSafetyDetector, TextSafetyMatch

logger = logging.getLogger(__name__)
_METER = get_meter("fortifyroot.safety")
_RULES_EVALUATED_COUNTER = _METER.create_counter(
    "fortifyroot.safety.rules_evaluated",
    description="Number of safety rules evaluated against text inputs.",
)
_FINDINGS_PRODUCED_COUNTER = _METER.create_counter(
    "fortifyroot.safety.findings_produced",
    description="Number of safety findings produced by rule evaluation.",
)
_MASKS_APPLIED_COUNTER = _METER.create_counter(
    "fortifyroot.safety.masks_applied",
    description="Number of safety masks applied to text outputs.",
)
_UDF_ERRORS_COUNTER = _METER.create_counter(
    "fortifyroot.safety.udf_errors",
    description="Number of safety UDF load or execution errors.",
)

SDK_LANGUAGE_PYTHON = "PYTHON"
MAX_REGEX_PATTERN_LENGTH = 1024
MAX_REGEX_MATCHES = 1000


@dataclass(frozen=True, slots=True)
class CompiledSafetyRule:
    name: str
    category: str
    severity: str
    action: str
    regex: re.Pattern[str] | None
    list_values: tuple[str, ...]
    list_ignore_case: bool
    udf_detector: TextSafetyDetector | None


@dataclass(frozen=True, slots=True)
class CompiledSafetySnapshot:
    config_profile_id: str
    version: int
    etag: str
    enabled: bool
    rules: tuple[CompiledSafetyRule, ...]

    def evaluate_text(self, text: str) -> SafetyResult | None:
        if not self.enabled or not text:
            return None

        findings: list[SafetyFinding] = []
        for rule in self.rules:
            findings.extend(_evaluate_rule(rule, text))

        if not findings:
            return None

        overall_action = _resolve_overall_action(findings)
        masked_text = _apply_masks(text, findings)

        return SafetyResult(
            text=masked_text,
            findings=tuple(findings),
            overall_action=overall_action,
        )


def compile_snapshot(profile: ConfigProfile) -> CompiledSafetySnapshot:
    if not profile.safety.enabled:
        return CompiledSafetySnapshot(
            config_profile_id=profile.config_profile_id,
            version=profile.version,
            etag=profile.etag,
            enabled=False,
            rules=(),
        )

    rules = []
    default_action = profile.safety.default_action or SafetyDecision.ALLOW.value
    for rule in profile.safety.rules:
        if not rule.enabled:
            continue
        compiled = _compile_rule(rule, default_action)
        if compiled is not None:
            rules.append(compiled)

    return CompiledSafetySnapshot(
        config_profile_id=profile.config_profile_id,
        version=profile.version,
        etag=profile.etag,
        enabled=profile.safety.enabled,
        rules=tuple(rules),
    )


def _compile_rule(rule: SafetyRule, default_action: str) -> CompiledSafetyRule | None:
    action = rule.action or default_action
    if action not in {
        SafetyDecision.ALLOW.value,
        SafetyDecision.MASK.value,
    }:
        logger.warning("Skipping safety rule with unsupported action: %s", rule.name)
        return None

    regex = None
    list_values: tuple[str, ...] = ()
    list_ignore_case = False
    udf_detector = None

    if isinstance(rule.matcher, RegexMatcher):
        if len(rule.matcher.pattern) > MAX_REGEX_PATTERN_LENGTH:
            logger.warning(
                "Skipping safety rule with oversized regex: %s",
                rule.name,
            )
            return None
        try:
            regex = re.compile(rule.matcher.pattern)
        except re.error:
            logger.warning("Skipping safety rule with invalid regex: %s", rule.name)
            return None
    elif isinstance(rule.matcher, StringListMatcher):
        list_values = tuple(value for value in rule.matcher.values if value)
        list_ignore_case = rule.matcher.ignore_case
        if not list_values:
            return None
    elif isinstance(rule.matcher, UdfMatcher):
        if rule.matcher.languages and SDK_LANGUAGE_PYTHON not in rule.matcher.languages:
            return None
        udf_detector = _load_detector(rule.matcher.entry_point)
        if udf_detector is None:
            return None
    else:
        return None

    return CompiledSafetyRule(
        name=rule.name,
        category=rule.category,
        severity=rule.severity,
        action=action,
        regex=regex,
        list_values=list_values,
        list_ignore_case=list_ignore_case,
        udf_detector=udf_detector,
    )


def _load_detector(entry_point: str) -> TextSafetyDetector | None:
    module_name, _, symbol_name = entry_point.partition(":")
    if not module_name or not symbol_name:
        logger.warning("Skipping UDF rule with invalid entry point: %s", entry_point)
        return None

    try:
        module = importlib.import_module(module_name)
    except Exception:
        logger.warning("Failed to import UDF module: %s", module_name)
        return None

    detector_obj = getattr(module, symbol_name, None)
    if detector_obj is None:
        logger.warning("Failed to resolve UDF symbol: %s", entry_point)
        return None

    if isinstance(detector_obj, TextSafetyDetector):
        return detector_obj

    if isinstance(detector_obj, type) and issubclass(detector_obj, TextSafetyDetector):
        try:
            return detector_obj()
        except Exception:
            logger.warning("Failed to instantiate UDF detector: %s", entry_point)
            return None

    logger.warning("Skipping unsupported UDF symbol type: %s", entry_point)
    return None


def _evaluate_rule(rule: CompiledSafetyRule, text: str) -> list[SafetyFinding]:
    metric_attributes = _rule_metric_attributes(rule)
    _RULES_EVALUATED_COUNTER.add(1, attributes=metric_attributes)

    if rule.regex is not None:
        findings: list[SafetyFinding] = []
        for match in rule.regex.finditer(text):
            if match.end() <= match.start():
                continue
            findings.append(_build_finding(rule, match.start(), match.end(), rule.name))
            if len(findings) >= MAX_REGEX_MATCHES:
                break
        if findings:
            _FINDINGS_PRODUCED_COUNTER.add(len(findings), attributes=metric_attributes)
        return findings

    if rule.list_values:
        findings = []
        for value in rule.list_values:
            findings.extend(
                _build_finding(rule, start, end, rule.name)
                for start, end in _find_literal_matches(text, value, rule.list_ignore_case)
            )
        if findings:
            _FINDINGS_PRODUCED_COUNTER.add(len(findings), attributes=metric_attributes)
        return findings

    if rule.udf_detector is not None:
        findings = []
        try:
            matches = rule.udf_detector.detect(text)
        except Exception:
            logger.warning("UDF detector execution failed: %s", rule.name)
            _UDF_ERRORS_COUNTER.add(1, attributes=metric_attributes)
            return findings
        for match in matches:
            if not isinstance(match, TextSafetyMatch):
                continue
            if not match.name or match.start < 0 or match.end <= match.start or match.end > len(text):
                continue
            findings.append(
                _build_finding(
                    rule,
                    match.start,
                    match.end,
                    f"{rule.name}.{match.name}",
                )
            )
        if findings:
            _FINDINGS_PRODUCED_COUNTER.add(len(findings), attributes=metric_attributes)
        return findings

    return []


def _build_finding(
    rule: CompiledSafetyRule,
    start: int,
    end: int,
    rule_name: str,
) -> SafetyFinding:
    return SafetyFinding(
        category=rule.category,
        severity=rule.severity,
        action=rule.action,
        rule_name=rule_name,
        start=start,
        end=end,
    )


def _resolve_overall_action(findings: Sequence[SafetyFinding]) -> str:
    actions = {finding.action for finding in findings}
    if SafetyDecision.MASK.value in actions:
        return SafetyDecision.MASK.value
    return SafetyDecision.ALLOW.value


def _apply_masks(text: str, findings: Sequence[SafetyFinding]) -> str:
    mask_segments = [
        (finding.start, finding.end, _mask_replacement(finding))
        for finding in findings
        if finding.action == SafetyDecision.MASK.value
    ]
    if not mask_segments:
        return text

    selected = []
    last_end = -1
    for start, end, replacement in sorted(mask_segments, key=lambda item: (item[0], -(item[1] - item[0]), item[2])):
        if start < last_end:
            continue
        selected.append((start, end, replacement))
        last_end = end

    if not selected:
        return text

    _MASKS_APPLIED_COUNTER.add(
        len(selected),
        attributes={"fortifyroot.safety.masked": "true"},
    )

    parts = []
    cursor = 0
    for start, end, replacement in selected:
        parts.append(text[cursor:start])
        parts.append(replacement)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _mask_replacement(finding: SafetyFinding) -> str:
    return f"[{finding.category}.{_sanitize_rule_name(finding.rule_name)}]"


def _sanitize_rule_name(rule_name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", rule_name or "rule")
    return sanitized.strip("._") or "rule"


def _find_literal_matches(
    text: str,
    needle: str,
    ignore_case: bool,
) -> Iterable[tuple[int, int]]:
    haystack = text.lower() if ignore_case else text
    token = needle.lower() if ignore_case else needle
    start = 0
    while token:
        index = haystack.find(token, start)
        if index == -1:
            break
        end = index + len(token)
        yield index, end
        start = end


def _rule_metric_attributes(rule: CompiledSafetyRule) -> dict[str, str]:
    return {
        "fortifyroot.safety.category": rule.category,
        "fortifyroot.safety.action": rule.action,
        "fortifyroot.safety.matcher": _rule_matcher_type(rule),
    }


def _rule_matcher_type(rule: CompiledSafetyRule) -> str:
    if rule.regex is not None:
        return "regex"
    if rule.list_values:
        return "list"
    if rule.udf_detector is not None:
        return "udf"
    return "unknown"

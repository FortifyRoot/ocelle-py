"""Tests for SDK-local safety parsing and evaluation."""

from types import SimpleNamespace
from unittest import mock

from fortifyroot._internal.safety import engine as safety_engine
from fortifyroot._internal.safety.engine import (
    CompiledSafetyRule,
    CompiledSafetySnapshot,
    _load_detector,
    compile_snapshot,
)
from fortifyroot._internal.safety.models import StringListMatcher, UdfMatcher
from fortifyroot._internal.safety.parser import parse_sdk_config_response
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyDecision,
)
from fortifyroot.safety import TextSafetyDetector, TextSafetyMatch


class SensitiveDetector(TextSafetyDetector):
    def detect(self, text: str):
        matches = []
        if "secret" in text:
            start = text.index("secret")
            matches.append(TextSafetyMatch(name="token", start=start, end=start + 6))
        return matches


class NoisyDetector(TextSafetyDetector):
    def detect(self, text: str):
        return [
            TextSafetyMatch(name="", start=0, end=3),
            TextSafetyMatch(name="negative", start=-1, end=3),
            TextSafetyMatch(name="overflow", start=0, end=len(text) + 5),
            TextSafetyMatch(name="ok", start=0, end=4),
        ]


class ExplodingDetector(TextSafetyDetector):
    def detect(self, text: str):
        raise RuntimeError("boom")


class BrokenDetector(TextSafetyDetector):
    def __init__(self):
        raise RuntimeError("broken ctor")

    def detect(self, text: str):
        return []


DetectorInstance = SensitiveDetector()


def test_parse_sdk_config_response_accepts_backend_json_shape():
    payload = {
        "configProfile": {
            "id": "cfg-1",
            "version": 7,
            "etag": "abc123",
            "config": {
                "safetyConfig": {
                    "enabled": True,
                    "defaultAction": "SAFETY_ACTION_MASK",
                    "rules": [
                        {
                            "name": "email",
                            "category": "SAFETY_CATEGORY_PII",
                            "severity": "SEVERITY_HIGH",
                            "enabled": True,
                            "regex": r"[a-z]+@[a-z]+\.com",
                        }
                    ],
                }
            },
        },
        "notModified": False,
    }

    parsed = parse_sdk_config_response(payload)

    assert parsed.not_modified is False
    assert parsed.config_profile is not None
    assert parsed.config_profile.config_profile_id == "cfg-1"
    assert parsed.config_profile.version == 7
    assert parsed.config_profile.etag == "abc123"
    assert parsed.config_profile.safety.enabled is True
    assert parsed.config_profile.safety.default_action == "MASK"
    assert parsed.config_profile.safety.rules[0].category == "PII"


def test_parse_sdk_config_response_skips_invalid_rules_and_accepts_snake_case_matchers():
    payload = {
        "config_profile": {
            "id": "cfg-2",
            "version": 1,
            "etag": "etag-2",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "MASK",
                    "rules": [
                        {
                            "name": "literal_secret",
                            "category": "SECRET",
                            "severity": "LOW",
                            "enabled": True,
                            "list_matcher": {"values": ["secret"], "ignore_case": True},
                        },
                        {
                            "name": "Detector",
                            "category": "PII",
                            "severity": "HIGH",
                            "enabled": True,
                            "udf_matcher": {
                                "entry_point": "tests.test_safety_engine:SensitiveDetector",
                                "languages": ["SDK_LANGUAGE_PYTHON"],
                            },
                        },
                        {
                            "name": "",
                            "category": "PII",
                            "severity": "HIGH",
                            "enabled": True,
                            "regex": "x",
                        },
                        {
                            "name": "missing_category",
                            "severity": "HIGH",
                            "enabled": True,
                            "regex": "x",
                        },
                    ],
                }
            },
        },
        "not_modified": False,
    }

    parsed = parse_sdk_config_response(payload)

    assert parsed.config_profile is not None
    assert [rule.name for rule in parsed.config_profile.safety.rules] == [
        "literal_secret",
        "Detector",
    ]


def test_parse_sdk_config_response_skips_unknown_and_numeric_categories():
    payload = {
        "config_profile": {
            "id": "cfg-invalid-category",
            "version": 1,
            "etag": "etag-invalid-category",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "MASK",
                    "rules": [
                        {
                            "name": "unknown_category",
                            "category": "not-real",
                            "severity": "HIGH",
                            "enabled": True,
                            "regex": "secret",
                        },
                        {
                            "name": "numeric_category",
                            "category": 1,
                            "severity": "HIGH",
                            "enabled": True,
                            "regex": "secret",
                        },
                    ],
                }
            },
        }
    }

    parsed = parse_sdk_config_response(payload)

    assert parsed.config_profile is not None
    assert parsed.config_profile.safety.rules == ()


def test_compile_snapshot_evaluates_regex_list_and_udf_matches():
    payload = {
        "config_profile": {
            "id": "cfg-1",
            "version": 2,
            "etag": "etag-1",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "ALLOW",
                    "rules": [
                        {
                            "name": "email",
                            "category": "PII",
                            "severity": "HIGH",
                            "action": "MASK",
                            "enabled": True,
                            "regex": r"[a-z]+@[a-z]+\.com",
                        },
                        {
                            "name": "secret_words",
                            "category": "SECRET",
                            "severity": "MEDIUM",
                            "action": "ALLOW",
                            "enabled": True,
                            "list": {"values": ["do-not-mask"], "ignore_case": True},
                        },
                        {
                            "name": "SensitiveDetector",
                            "category": "SECRET",
                            "severity": "HIGH",
                            "action": "MASK",
                            "enabled": True,
                            "udf": {
                                "entry_point": "tests.test_safety_engine:SensitiveDetector",
                                "languages": ["SDK_LANGUAGE_PYTHON"],
                            },
                        },
                    ],
                }
            },
        },
        "not_modified": False,
    }

    parsed = parse_sdk_config_response(payload)
    snapshot = compile_snapshot(parsed.config_profile)
    result = snapshot.evaluate_text("email me at jane@acme.com with secret and do-not-mask")

    assert result is not None
    assert result.overall_action == SafetyDecision.MASK.value
    assert "[PII.email]" in result.text
    assert "[SECRET.SensitiveDetector.token]" in result.text
    assert any(f.rule_name == "SensitiveDetector.token" for f in result.findings)
    assert any(f.rule_name == "secret_words" and f.action == "ALLOW" for f in result.findings)


def test_compile_snapshot_skips_block_rules_in_python_sdk():
    payload = {
        "config_profile": {
            "id": "cfg-1",
            "version": 1,
            "etag": "etag-2",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "MASK",
                    "rules": [
                        {
                            "name": "email",
                            "category": "PII",
                            "severity": "HIGH",
                            "action": "MASK",
                            "enabled": True,
                            "regex": r"[a-z]+@[a-z]+\.com",
                        },
                        {
                            "name": "blocker",
                            "category": "SECRET",
                            "severity": "CRITICAL",
                            "action": "BLOCK",
                            "enabled": True,
                            "list": {"values": ["secret"], "ignore_case": False},
                        },
                    ],
                }
            },
        }
    }

    parsed = parse_sdk_config_response(payload)
    snapshot = compile_snapshot(parsed.config_profile)
    result = snapshot.evaluate_text("email jane@acme.com and secret")

    assert result is not None
    assert [rule.name for rule in snapshot.rules] == ["email"]
    assert result.overall_action == SafetyDecision.MASK.value
    assert all(f.action != "BLOCK" for f in result.findings)


def test_compile_snapshot_skips_invalid_matchers_and_applies_default_action():
    payload = {
        "config_profile": {
            "id": "cfg-3",
            "version": 1,
            "etag": "etag-3",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "MASK",
                    "rules": [
                        {
                            "name": "broken_regex",
                            "category": "PII",
                            "severity": "HIGH",
                            "enabled": True,
                            "regex": "(",
                        },
                        {
                            "name": "ts_only_udf",
                            "category": "PII",
                            "severity": "HIGH",
                            "enabled": True,
                            "udf": {
                                "entry_point": "tests.test_safety_engine:SensitiveDetector",
                                "languages": ["SDK_LANGUAGE_TYPESCRIPT"],
                            },
                        },
                        {
                            "name": "secret_word",
                            "category": "SECRET",
                            "severity": "MEDIUM",
                            "enabled": True,
                            "list": {"values": ["secret", "secret"], "ignore_case": False},
                        },
                    ],
                }
            },
        }
    }

    parsed = parse_sdk_config_response(payload)
    snapshot = compile_snapshot(parsed.config_profile)
    result = snapshot.evaluate_text("secret")

    assert [rule.name for rule in snapshot.rules] == ["secret_word"]
    assert result is not None
    assert result.overall_action == SafetyDecision.MASK.value
    assert result.text == "[SECRET.secret_word]"


def test_compile_snapshot_masks_overlaps_deterministically():
    payload = {
        "config_profile": {
            "id": "cfg-4",
            "version": 1,
            "etag": "etag-4",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "MASK",
                    "rules": [
                        {
                            "name": "short_secret",
                            "category": "SECRET",
                            "severity": "MEDIUM",
                            "action": "MASK",
                            "enabled": True,
                            "list": {"values": ["secret"], "ignore_case": False},
                        },
                        {
                            "name": "long_secret",
                            "category": "SECRET",
                            "severity": "HIGH",
                            "action": "MASK",
                            "enabled": True,
                            "regex": r"secret-\d+",
                        },
                    ],
                }
            },
        }
    }

    parsed = parse_sdk_config_response(payload)
    snapshot = compile_snapshot(parsed.config_profile)
    result = snapshot.evaluate_text("secret-123")

    assert result is not None
    assert result.text == "[SECRET.long_secret]"
    assert {finding.rule_name for finding in result.findings} == {
        "short_secret",
        "long_secret",
    }


def test_compile_snapshot_ignores_invalid_udf_submatches():
    payload = {
        "config_profile": {
            "id": "cfg-5",
            "version": 1,
            "etag": "etag-5",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "ALLOW",
                    "rules": [
                        {
                            "name": "NoisyDetector",
                            "category": "PII",
                            "severity": "HIGH",
                            "action": "MASK",
                            "enabled": True,
                            "udf": {
                                "entry_point": "tests.test_safety_engine:NoisyDetector",
                                "languages": ["SDK_LANGUAGE_PYTHON"],
                            },
                        }
                    ],
                }
            },
        }
    }

    parsed = parse_sdk_config_response(payload)
    snapshot = compile_snapshot(parsed.config_profile)
    result = snapshot.evaluate_text("abcd")

    assert result is not None
    assert result.text == "[PII.NoisyDetector.ok]"
    assert [finding.rule_name for finding in result.findings] == ["NoisyDetector.ok"]


def test_compile_snapshot_returns_none_when_disabled_or_without_matches():
    disabled_snapshot = CompiledSafetySnapshot(
        config_profile_id="cfg-disabled",
        version=1,
        etag="etag-disabled",
        enabled=False,
        rules=(),
    )
    enabled_snapshot = CompiledSafetySnapshot(
        config_profile_id="cfg-empty",
        version=1,
        etag="etag-empty",
        enabled=True,
        rules=(),
    )

    assert disabled_snapshot.evaluate_text("secret") is None
    assert enabled_snapshot.evaluate_text("secret") is None


def test_compile_snapshot_skips_rule_compilation_when_safety_is_disabled():
    profile = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-disabled-compile",
                "version": 1,
                "etag": "etag-disabled-compile",
                "config": {
                    "safety_config": {
                        "enabled": False,
                        "default_action": "MASK",
                        "rules": [
                            {
                                "name": "expensive_udf",
                                "category": "SECRET",
                                "severity": "HIGH",
                                "enabled": True,
                                "udf": {
                                    "entry_point": "tests.test_safety_engine:SensitiveDetector",
                                    "languages": ["SDK_LANGUAGE_PYTHON"],
                                },
                            }
                        ],
                    }
                },
            }
        }
    ).config_profile

    snapshot = compile_snapshot(profile)

    assert snapshot.enabled is False
    assert snapshot.rules == ()


def test_compile_snapshot_supports_allow_only_matches_without_masking():
    profile = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-allow",
                "version": 1,
                "etag": "etag-allow",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "ALLOW",
                        "rules": [
                            {
                                "name": "secret_word",
                                "category": "SECRET",
                                "severity": "LOW",
                                "enabled": True,
                                "list": {"values": ["secret"], "ignore_case": False},
                            }
                        ],
                    }
                },
            }
        }
    ).config_profile

    snapshot = compile_snapshot(profile)
    result = snapshot.evaluate_text("secret")

    assert result is not None
    assert result.overall_action == SafetyDecision.ALLOW.value
    assert result.text == "secret"


def test_compile_snapshot_skips_unsupported_action_and_empty_list_rules():
    profile = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-skip",
                "version": 1,
                "etag": "etag-skip",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "ALLOW",
                        "rules": [
                            {
                                "name": "bad_action",
                                "category": "SECRET",
                                "severity": "LOW",
                                "action": "quarantine",
                                "enabled": True,
                                "regex": "secret",
                            },
                            {
                                "name": "empty_list",
                                "category": "SECRET",
                                "severity": "LOW",
                                "enabled": True,
                                "list": {"values": ["", ""], "ignore_case": False},
                            },
                        ],
                    }
                },
            }
        }
    ).config_profile

    snapshot = compile_snapshot(profile)

    assert snapshot.rules == ()


def test_load_detector_supports_instance_and_rejects_bad_entry_points():
    assert _load_detector("tests.test_safety_engine:DetectorInstance") is DetectorInstance
    assert _load_detector("tests.test_safety_engine") is None
    assert _load_detector("tests.test_safety_engine:MissingSymbol") is None
    assert _load_detector("tests.test_safety_engine:BrokenDetector") is None
    assert _load_detector("tests.test_safety_engine:NoisyDetector") is not None
    assert _load_detector("tests.test_safety_engine:123") is None


def test_compile_snapshot_handles_detector_execution_failure_and_empty_masks():
    profile = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-udf-error",
                "version": 1,
                "etag": "etag-udf-error",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "MASK",
                        "rules": [
                            {
                                "name": "ExplodingDetector",
                                "category": "SECRET",
                                "severity": "HIGH",
                                "enabled": True,
                                "udf": {
                                    "entry_point": "tests.test_safety_engine:ExplodingDetector",
                                    "languages": ["SDK_LANGUAGE_PYTHON"],
                                },
                            }
                        ],
                    }
                },
            }
        }
    ).config_profile

    snapshot = compile_snapshot(profile)

    assert snapshot.evaluate_text("secret") is None

    empty_rule = CompiledSafetyRule(
        name="empty",
        category="SECRET",
        severity="LOW",
        action="ALLOW",
        regex=None,
        list_values=(),
        list_ignore_case=False,
        udf_detector=None,
    )
    empty_snapshot = CompiledSafetySnapshot(
        config_profile_id="cfg-empty-rule",
        version=1,
        etag="etag-empty-rule",
        enabled=True,
        rules=(empty_rule,),
    )
    assert empty_snapshot.evaluate_text("secret") is None


def test_parse_sdk_config_response_handles_invalid_rule_shapes_and_scalar_values():
    parsed = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-parser",
                "version": True,
                "etag": "etag-parser",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "invalid-action",
                        "rules": [
                            123,
                            {
                                "name": "with_defaults",
                                "category": "SAFETY_CATEGORY_SECRET",
                                "severity": "bad-severity",
                                "enabled": True,
                                "list": {"values": ["secret", 123], "ignore_case": False},
                            },
                            {
                                "name": "missing_matcher",
                                "category": "SECRET",
                                "enabled": True,
                            },
                            {
                                "name": "udf_rule",
                                "category": "PII",
                                "enabled": True,
                                "udf": {
                                    "entry_point": "tests.test_safety_engine:SensitiveDetector",
                                    "languages": ["SDK_LANGUAGE_PYTHON", "weird"],
                                },
                            },
                        ],
                    }
                },
            },
            "not_modified": 0,
        }
    )

    assert parsed.not_modified is False
    assert parsed.config_profile.version == 1
    assert parsed.config_profile.safety.default_action == "ALLOW"
    assert [rule.name for rule in parsed.config_profile.safety.rules] == [
        "with_defaults",
        "udf_rule",
    ]
    assert parsed.config_profile.safety.rules[0].severity == "MEDIUM"
    assert isinstance(parsed.config_profile.safety.rules[0].matcher, StringListMatcher)
    assert isinstance(parsed.config_profile.safety.rules[1].matcher, UdfMatcher)


def test_parse_sdk_config_response_dedupes_list_values_and_drops_unknown_actions():
    parsed = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-parser-dedup",
                "version": 1,
                "etag": "etag-parser-dedup",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "MASK",
                        "rules": [
                            {
                                "name": "secret_words",
                                "category": "SECRET",
                                "severity": "LOW",
                                "enabled": True,
                                "list": {
                                    "values": ["secret", "secret", "token"],
                                    "ignore_case": True,
                                },
                            },
                            {
                                "name": "unsupported_action",
                                "category": "SECRET",
                                "severity": "LOW",
                                "action": "QUARANTINE",
                                "enabled": True,
                                "regex": "secret",
                            }
                        ],
                    }
                },
            }
        }
    )

    rule = parsed.config_profile.safety.rules[0]

    assert [item.name for item in parsed.config_profile.safety.rules] == ["secret_words"]
    assert rule.action is None
    assert isinstance(rule.matcher, StringListMatcher)
    assert rule.matcher.values == ("secret", "token")


def test_compile_snapshot_skips_oversized_regex_patterns_and_caps_regex_matches():
    oversized_profile = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-oversized",
                "version": 1,
                "etag": "etag-oversized",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "MASK",
                        "rules": [
                            {
                                "name": "too_big",
                                "category": "SECRET",
                                "severity": "HIGH",
                                "enabled": True,
                                "regex": "a" * (safety_engine.MAX_REGEX_PATTERN_LENGTH + 1),
                            }
                        ],
                    }
                },
            }
        }
    ).config_profile

    oversized_snapshot = compile_snapshot(oversized_profile)
    assert oversized_snapshot.rules == ()

    capped_profile = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-regex-cap",
                "version": 1,
                "etag": "etag-regex-cap",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "ALLOW",
                        "rules": [
                            {
                                "name": "any_char",
                                "category": "SECRET",
                                "severity": "LOW",
                                "enabled": True,
                                "regex": ".",
                            }
                        ],
                    }
                },
            }
        }
    ).config_profile

    capped_snapshot = compile_snapshot(capped_profile)
    result = capped_snapshot.evaluate_text("a" * (safety_engine.MAX_REGEX_MATCHES + 25))

    assert result is not None
    assert len(result.findings) == safety_engine.MAX_REGEX_MATCHES
    assert result.overall_action == SafetyDecision.ALLOW.value


def test_engine_records_rule_evaluation_mask_and_udf_error_metrics():
    rules_counter = mock.Mock()
    findings_counter = mock.Mock()
    masks_counter = mock.Mock()
    udf_errors_counter = mock.Mock()

    original_rules_counter = safety_engine._RULES_EVALUATED_COUNTER
    original_findings_counter = safety_engine._FINDINGS_PRODUCED_COUNTER
    original_masks_counter = safety_engine._MASKS_APPLIED_COUNTER
    original_udf_errors_counter = safety_engine._UDF_ERRORS_COUNTER

    safety_engine._RULES_EVALUATED_COUNTER = SimpleNamespace(add=rules_counter)
    safety_engine._FINDINGS_PRODUCED_COUNTER = SimpleNamespace(add=findings_counter)
    safety_engine._MASKS_APPLIED_COUNTER = SimpleNamespace(add=masks_counter)
    safety_engine._UDF_ERRORS_COUNTER = SimpleNamespace(add=udf_errors_counter)
    try:
        masked_profile = parse_sdk_config_response(
            {
                "config_profile": {
                    "id": "cfg-metrics",
                    "version": 1,
                    "etag": "etag-metrics",
                    "config": {
                        "safety_config": {
                            "enabled": True,
                            "default_action": "MASK",
                            "rules": [
                                {
                                    "name": "secret_word",
                                    "category": "SECRET",
                                    "severity": "HIGH",
                                    "enabled": True,
                                    "list": {"values": ["secret"], "ignore_case": False},
                                }
                            ],
                        }
                    },
                }
            }
        ).config_profile
        masked_snapshot = compile_snapshot(masked_profile)

        result = masked_snapshot.evaluate_text("secret")

        assert result is not None
        assert result.text == "[SECRET.secret_word]"

        exploding_profile = parse_sdk_config_response(
            {
                "config_profile": {
                    "id": "cfg-udf-metrics",
                    "version": 1,
                    "etag": "etag-udf-metrics",
                    "config": {
                        "safety_config": {
                            "enabled": True,
                            "default_action": "MASK",
                            "rules": [
                                {
                                    "name": "ExplodingDetector",
                                    "category": "SECRET",
                                    "severity": "HIGH",
                                    "enabled": True,
                                    "udf": {
                                        "entry_point": "tests.test_safety_engine:ExplodingDetector",
                                        "languages": ["SDK_LANGUAGE_PYTHON"],
                                    },
                                }
                            ],
                        }
                    },
                }
            }
        ).config_profile
        exploding_snapshot = compile_snapshot(exploding_profile)

        assert exploding_snapshot.evaluate_text("secret") is None
    finally:
        safety_engine._RULES_EVALUATED_COUNTER = original_rules_counter
        safety_engine._FINDINGS_PRODUCED_COUNTER = original_findings_counter
        safety_engine._MASKS_APPLIED_COUNTER = original_masks_counter
        safety_engine._UDF_ERRORS_COUNTER = original_udf_errors_counter

    assert rules_counter.call_count >= 2
    findings_counter.assert_called_once()
    masks_counter.assert_called_once_with(
        1,
        attributes={"fortifyroot.safety.masked": "true"},
    )
    udf_errors_counter.assert_called_once()

"""Tests for SDK-local safety parsing and evaluation."""

import logging
from types import SimpleNamespace
from unittest import mock

import pytest

from fortifyroot._internal.safety import engine as safety_engine
from fortifyroot._internal.safety.engine import (
    CompiledSafetyRule,
    CompiledSafetySnapshot,
    _load_detector,
    compile_snapshot,
    set_udf_detectors_enabled,
)
from fortifyroot._internal.safety.models import StringListMatcher, UdfMatcher
from fortifyroot._internal.safety.parser import parse_sdk_config_response
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyDecision,
)
from fortifyroot.safety import TextSafetyDetector, TextSafetyMatch


@pytest.fixture(autouse=True)
def _enable_udf_detectors():
    """Enable UDF detectors for all tests in this module by default.

    Individual tests that verify the guard behaviour override this via
    explicit ``set_udf_detectors_enabled(False)`` calls.
    """
    set_udf_detectors_enabled(True)
    yield
    set_udf_detectors_enabled(False)


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


def test_compile_snapshot_treats_unspecified_rule_action_as_default_override():
    payload = {
        "config_profile": {
            "id": "cfg-unspecified-action",
            "version": 1,
            "etag": "etag-unspecified-action",
            "config": {
                "safety_config": {
                    "enabled": True,
                    "default_action": "MASK",
                    "rules": [
                        {
                            "name": "email",
                            "category": "PII",
                            "severity": "HIGH",
                            "action": "SAFETY_ACTION_UNSPECIFIED",
                            "enabled": True,
                            "regex": r"[a-z]+@[a-z]+\.com",
                        },
                    ],
                }
            },
        }
    }

    parsed = parse_sdk_config_response(payload)
    snapshot = compile_snapshot(parsed.config_profile)
    result = snapshot.evaluate_text("email jane@acme.com")

    assert [rule.name for rule in snapshot.rules] == ["email"]
    assert parsed.config_profile.safety.rules[0].action is None
    assert result is not None
    assert result.overall_action == SafetyDecision.MASK.value
    assert result.text == "email [PII.email]"


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


def test_parse_sdk_config_response_dedupes_list_values_and_tolerates_unspecified_action():
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
                            },
                            {
                                "name": "unspecified_action",
                                "category": "SECRET",
                                "severity": "LOW",
                                "action": "SAFETY_ACTION_UNSPECIFIED",
                                "enabled": True,
                                "regex": "secret",
                            }
                        ],
                    }
                },
            }
        }
    )

    names = [item.name for item in parsed.config_profile.safety.rules]

    assert names == ["secret_words", "unspecified_action"]
    assert parsed.config_profile.safety.rules[0].action is None
    assert isinstance(parsed.config_profile.safety.rules[0].matcher, StringListMatcher)
    assert parsed.config_profile.safety.rules[0].matcher.values == ("secret", "token")
    assert parsed.config_profile.safety.rules[1].action is None


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


# ---- Additional coverage tests ----


class MixedReturnDetector(TextSafetyDetector):
    """Returns a mix of valid TextSafetyMatch items and invalid non-match objects."""

    def detect(self, text: str):
        return [
            "not-a-match",
            42,
            None,
            TextSafetyMatch(name="real", start=0, end=min(4, len(text))),
        ]


# A plain object that is NOT a TextSafetyDetector
NotADetector = "just a string"


def test_compile_snapshot_skips_disabled_rules():
    """Cover line 106: disabled rule causes 'continue' in compile_snapshot loop."""
    from fortifyroot._internal.safety.models import (
        ConfigProfile,
        RegexMatcher,
        SafetyConfig,
        SafetyRule,
    )

    profile = ConfigProfile(
        config_profile_id="cfg-disabled-rule",
        version=1,
        etag="etag-disabled-rule",
        safety=SafetyConfig(
            enabled=True,
            default_action="MASK",
            rules=(
                SafetyRule(
                    name="disabled_rule",
                    category="PII",
                    severity="HIGH",
                    action="MASK",
                    enabled=False,
                    matcher=RegexMatcher(pattern="secret"),
                ),
                SafetyRule(
                    name="enabled_rule",
                    category="SECRET",
                    severity="LOW",
                    action="MASK",
                    enabled=True,
                    matcher=RegexMatcher(pattern="token"),
                ),
            ),
        ),
    )

    snapshot = compile_snapshot(profile)

    assert len(snapshot.rules) == 1
    assert snapshot.rules[0].name == "enabled_rule"


def test_compile_rule_skips_unsupported_action():
    """Cover lines 126-127: rule with unsupported action returns None."""
    from fortifyroot._internal.safety.engine import _compile_rule
    from fortifyroot._internal.safety.models import RegexMatcher, SafetyRule

    rule = SafetyRule(
        name="block_rule",
        category="PII",
        severity="HIGH",
        action="BLOCK",
        enabled=True,
        matcher=RegexMatcher(pattern="secret"),
    )

    result = _compile_rule(rule, default_action="BLOCK")

    assert result is None


def test_compile_rule_returns_none_for_failed_udf_load():
    """Cover lines 155-156: UDF detector load fails -> _compile_rule returns None."""
    from fortifyroot._internal.safety.engine import _compile_rule
    from fortifyroot._internal.safety.models import SafetyRule, UdfMatcher

    rule = SafetyRule(
        name="bad_udf",
        category="PII",
        severity="HIGH",
        action="MASK",
        enabled=True,
        matcher=UdfMatcher(
            entry_point="nonexistent.module:Detector",
            languages=("PYTHON",),
        ),
    )

    result = _compile_rule(rule, default_action="MASK")

    assert result is None


def test_compile_rule_returns_none_for_unknown_matcher_type():
    """Cover lines 157-158: unknown matcher type falls through all branches."""
    from fortifyroot._internal.safety.engine import _compile_rule
    from fortifyroot._internal.safety.models import SafetyRule

    # Create a rule with a matcher that isn't RegexMatcher, StringListMatcher, or UdfMatcher
    rule = SafetyRule(
        name="weird_matcher",
        category="PII",
        severity="HIGH",
        action="MASK",
        enabled=True,
        matcher="not-a-real-matcher",
    )

    result = _compile_rule(rule, default_action="MASK")

    assert result is None


def test_load_detector_handles_import_failure():
    """Cover lines 180-182: importlib.import_module raises an exception."""
    result = _load_detector("this.module.does.not.exist:SomeDetector")

    assert result is None


def test_load_detector_rejects_non_detector_symbol():
    """Cover lines 199-200: symbol exists but is not a TextSafetyDetector type."""
    result = _load_detector("tests.test_safety_engine:NotADetector")

    assert result is None


def test_evaluate_rule_skips_zero_length_regex_matches():
    """Cover line 211: zero-length regex match (end <= start) is skipped."""
    # A regex like (?=a) matches zero-length positions before 'a'
    import re

    rule = CompiledSafetyRule(
        name="zero_len",
        category="PII",
        severity="HIGH",
        action="MASK",
        regex=re.compile(r"(?=a)"),
        list_values=(),
        list_ignore_case=False,
        udf_detector=None,
    )

    snapshot = CompiledSafetySnapshot(
        config_profile_id="cfg-zero-len",
        version=1,
        etag="etag-zero-len",
        enabled=True,
        rules=(rule,),
    )

    # The regex matches zero-length at every 'a', but all matches have end==start
    result = snapshot.evaluate_text("aaa")

    assert result is None


def test_evaluate_rule_skips_non_text_safety_match_from_udf():
    """Cover line 240: UDF returns non-TextSafetyMatch items which are skipped."""
    rule = CompiledSafetyRule(
        name="mixed_udf",
        category="PII",
        severity="HIGH",
        action="MASK",
        regex=None,
        list_values=(),
        list_ignore_case=False,
        udf_detector=MixedReturnDetector(),
    )

    snapshot = CompiledSafetySnapshot(
        config_profile_id="cfg-mixed-udf",
        version=1,
        etag="etag-mixed-udf",
        enabled=True,
        rules=(rule,),
    )

    result = snapshot.evaluate_text("abcdefgh")

    assert result is not None
    # Only the valid TextSafetyMatch ("real") should produce a finding
    assert len(result.findings) == 1
    assert result.findings[0].rule_name == "mixed_udf.real"


def test_apply_masks_deduplicates_overlapping_segments():
    """Cover the overlap filtering branch in _apply_masks (lines 293-294, 299)."""
    from fortifyroot._internal.safety.engine import _apply_masks
    from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
        SafetyFinding,
    )

    # Two overlapping MASK findings: wide [0,10) and narrow [2,5).
    # After sorting by (start, -length), the wider one is selected first
    # and the narrower one is skipped because its start < last_end.
    findings = [
        SafetyFinding(
            category="PII",
            severity="HIGH",
            action="MASK",
            rule_name="wide_rule",
            start=0,
            end=10,
        ),
        SafetyFinding(
            category="PII",
            severity="HIGH",
            action="MASK",
            rule_name="narrow_rule",
            start=2,
            end=5,
        ),
    ]

    result = _apply_masks("0123456789abcdef", findings)

    # The wider segment [0,10) should win, the narrower [2,5) is skipped
    assert "[PII.wide_rule]" in result
    assert "[PII.narrow_rule]" not in result
    assert result.endswith("abcdef")


def test_evaluate_text_returns_none_for_empty_text():
    """Cover the empty text branch in evaluate_text (line 72)."""
    rule = CompiledSafetyRule(
        name="email",
        category="PII",
        severity="HIGH",
        action="MASK",
        regex=None,
        list_values=("secret",),
        list_ignore_case=False,
        udf_detector=None,
    )

    snapshot = CompiledSafetySnapshot(
        config_profile_id="cfg-empty-text",
        version=1,
        etag="etag-empty-text",
        enabled=True,
        rules=(rule,),
    )

    assert snapshot.evaluate_text("") is None


def test_udf_findings_counter_path_with_valid_matches():
    """Cover line 251: UDF evaluation produces valid findings and hits the counter."""
    rule = CompiledSafetyRule(
        name="sensitive",
        category="SECRET",
        severity="HIGH",
        action="ALLOW",
        regex=None,
        list_values=(),
        list_ignore_case=False,
        udf_detector=SensitiveDetector(),
    )

    snapshot = CompiledSafetySnapshot(
        config_profile_id="cfg-udf-findings",
        version=1,
        etag="etag-udf-findings",
        enabled=True,
        rules=(rule,),
    )

    result = snapshot.evaluate_text("this has secret data")

    assert result is not None
    assert len(result.findings) == 1
    assert result.findings[0].rule_name == "sensitive.token"
    assert result.overall_action == "ALLOW"


# ---- UDF opt-in guard tests ----


class TestUdfDetectorGuard:
    """_load_detector must respect the _udf_detectors_enabled flag."""

    def test_load_detector_returns_none_when_udf_not_enabled(self, caplog) -> None:
        """When UDF detectors are disabled, _load_detector returns None and logs a warning."""
        set_udf_detectors_enabled(False)

        with caplog.at_level(logging.WARNING):
            result = _load_detector("some.module:Detector")

        assert result is None
        assert any(
            "UDF detector" in record.message and "skipped" in record.message
            for record in caplog.records
        )

    def test_load_detector_works_when_udf_enabled(self) -> None:
        """When UDF detectors are enabled, _load_detector loads the module normally."""
        set_udf_detectors_enabled(True)

        entry_point = "tests.test_safety_engine:SensitiveDetector"
        result = _load_detector(entry_point)

        assert result is not None
        assert isinstance(result, TextSafetyDetector)

    def test_load_detector_returns_none_for_invalid_entry_point_when_enabled(self, caplog) -> None:
        """Even when enabled, an invalid entry point still returns None."""
        set_udf_detectors_enabled(True)

        with caplog.at_level(logging.WARNING):
            result = _load_detector("no_colon_here")

        assert result is None

    def test_load_detector_returns_none_for_missing_module_when_enabled(self, caplog) -> None:
        """Even when enabled, a missing module returns None."""
        set_udf_detectors_enabled(True)

        with caplog.at_level(logging.WARNING):
            result = _load_detector("nonexistent.module:Detector")

        assert result is None


# ---- D-18: ReDoS residual - re2 with timeout fallback ----


class TestRegexTimeoutFallback:
    """Tests for _safe_finditer and the re2/stdlib fallback logic."""

    def test_safe_finditer_returns_matches_with_stdlib_re(self):
        """_safe_finditer should return matches when using stdlib re."""
        import re

        from fortifyroot._internal.safety.engine import _safe_finditer

        pattern = re.compile(r"\d+")
        matches = _safe_finditer(pattern, "abc 123 def 456", "test_rule")
        assert len(matches) == 2
        assert matches[0].group() == "123"
        assert matches[1].group() == "456"

    def test_safe_finditer_returns_empty_on_timeout(self, caplog):
        """_safe_finditer should raise _RegexTimeoutError on timeout and log a warning."""
        import concurrent.futures
        import re

        from fortifyroot._internal.safety.engine import (
            REGEX_EVAL_TIMEOUT_SECONDS,
            _RegexTimeoutError,
            _safe_finditer,
        )

        pattern = re.compile(r"\d+")

        with (
            caplog.at_level(logging.WARNING),
            mock.patch("fortifyroot._internal.safety.engine._USING_RE2", False),
            mock.patch(
                "fortifyroot._internal.safety.engine.concurrent.futures.ThreadPoolExecutor"
            ) as mock_pool_cls,
        ):
            mock_pool = mock.MagicMock()
            mock_pool_cls.return_value.__enter__ = mock.Mock(return_value=mock_pool)
            mock_pool_cls.return_value.__exit__ = mock.Mock(return_value=False)
            mock_future = mock.Mock()
            mock_future.result.side_effect = concurrent.futures.TimeoutError()
            mock_pool.submit.return_value = mock_future

            with pytest.raises(_RegexTimeoutError):
                _safe_finditer(pattern, "abc 123", "slow_rule")

        assert any("timed out" in record.message for record in caplog.records)

    def test_evaluate_rule_returns_empty_on_regex_timeout(self):
        """D-18: When regex evaluation times out, _evaluate_rule returns empty findings."""
        import re

        from fortifyroot._internal.safety.engine import _RegexTimeoutError, _evaluate_rule

        rule = CompiledSafetyRule(
            name="slow_regex",
            category="PII",
            severity="HIGH",
            action="MASK",
            regex=re.compile(r"\d+"),
            list_values=(),
            list_ignore_case=False,
            udf_detector=None,
        )

        with mock.patch(
            "fortifyroot._internal.safety.engine._safe_finditer",
            side_effect=_RegexTimeoutError(),
        ):
            findings = _evaluate_rule(rule, "abc 123 def")

        assert findings == []

    def test_using_re2_flag_and_re_engine(self):
        """Verify _USING_RE2 and _re_engine are set correctly (google-re2 required)."""
        import re2

        from fortifyroot._internal.safety.engine import _USING_RE2, _re_engine

        # google-re2 is a required dependency; re2 must be active.
        assert _USING_RE2 is True
        assert _re_engine is re2

    def test_regex_eval_timeout_constant_exists(self):
        """REGEX_EVAL_TIMEOUT_SECONDS should be 5."""
        from fortifyroot._internal.safety.engine import REGEX_EVAL_TIMEOUT_SECONDS

        assert REGEX_EVAL_TIMEOUT_SECONDS == 5


# ---- D-20: No match count cap for string list matcher ----


class TestListMatcherCap:
    """Tests for the match count cap on the string list matcher."""

    def test_list_matcher_caps_findings_at_max_regex_matches(self):
        """D-20: List matcher should cap findings at MAX_REGEX_MATCHES."""
        rule = CompiledSafetyRule(
            name="a_finder",
            category="PII",
            severity="LOW",
            action="ALLOW",
            regex=None,
            list_values=("a",),
            list_ignore_case=False,
            udf_detector=None,
        )

        snapshot = CompiledSafetySnapshot(
            config_profile_id="cfg-list-cap",
            version=1,
            etag="etag-list-cap",
            enabled=True,
            rules=(rule,),
        )

        text = "a" * (safety_engine.MAX_REGEX_MATCHES + 500)
        result = snapshot.evaluate_text(text)

        assert result is not None
        assert len(result.findings) == safety_engine.MAX_REGEX_MATCHES

    def test_list_matcher_cap_breaks_across_multiple_values(self):
        """D-20: Cap should apply across all list values, not per-value."""
        rule = CompiledSafetyRule(
            name="multi_finder",
            category="PII",
            severity="LOW",
            action="ALLOW",
            regex=None,
            list_values=("a", "b"),
            list_ignore_case=False,
            udf_detector=None,
        )

        snapshot = CompiledSafetySnapshot(
            config_profile_id="cfg-list-cap-multi",
            version=1,
            etag="etag-list-cap-multi",
            enabled=True,
            rules=(rule,),
        )

        # Many 'a's followed by many 'b's
        text = "a" * (safety_engine.MAX_REGEX_MATCHES + 100) + "b" * 100
        result = snapshot.evaluate_text(text)

        assert result is not None
        assert len(result.findings) == safety_engine.MAX_REGEX_MATCHES


# ---- D-21: No UDF match count cap ----


class ManyMatchDetector(TextSafetyDetector):
    """UDF that returns more matches than MAX_REGEX_MATCHES."""

    def detect(self, text: str):
        matches = []
        for i in range(len(text)):
            if i + 1 <= len(text):
                matches.append(TextSafetyMatch(name=f"m{i}", start=i, end=i + 1))
        return matches


class TestUdfMatchCountCap:
    """Tests for the UDF match count cap."""

    def test_udf_findings_capped_at_max_regex_matches(self):
        """D-21: UDF findings should be truncated to MAX_REGEX_MATCHES."""
        rule = CompiledSafetyRule(
            name="many_udf",
            category="PII",
            severity="LOW",
            action="ALLOW",
            regex=None,
            list_values=(),
            list_ignore_case=False,
            udf_detector=ManyMatchDetector(),
        )

        snapshot = CompiledSafetySnapshot(
            config_profile_id="cfg-udf-cap",
            version=1,
            etag="etag-udf-cap",
            enabled=True,
            rules=(rule,),
        )

        text = "x" * (safety_engine.MAX_REGEX_MATCHES + 500)
        result = snapshot.evaluate_text(text)

        assert result is not None
        assert len(result.findings) == safety_engine.MAX_REGEX_MATCHES


# ---- D-26: Unicode case-insensitive matching position drift ----


class TestUnicodeCaseInsensitiveMatching:
    """Tests for correct Unicode case-insensitive matching via re.finditer."""

    def test_case_insensitive_match_returns_correct_positions(self):
        """D-26: Case-insensitive matching should use re.finditer for correct positions."""
        from fortifyroot._internal.safety.engine import _find_literal_matches

        matches = list(_find_literal_matches("Hello HELLO hello", "hello", True))
        assert len(matches) == 3
        assert matches[0] == (0, 5)
        assert matches[1] == (6, 11)
        assert matches[2] == (12, 17)

    def test_unicode_sharp_s_case_insensitive(self):
        """D-26: German sharp s (\u00df) should match correctly with re.IGNORECASE."""
        from fortifyroot._internal.safety.engine import _find_literal_matches

        # In Unicode, \u00df (sharp s) lowercases to itself and has no single-char uppercase.
        # The re.IGNORECASE handles this correctly.
        text = "Stra\u00dfe"
        matches = list(_find_literal_matches(text, "stra\u00dfe", True))
        assert len(matches) == 1
        assert matches[0] == (0, 6)

    def test_case_sensitive_match_returns_correct_positions(self):
        """Case-sensitive matching should only find exact matches."""
        from fortifyroot._internal.safety.engine import _find_literal_matches

        matches = list(_find_literal_matches("Hello HELLO hello", "hello", False))
        assert len(matches) == 1
        assert matches[0] == (12, 17)

    def test_empty_needle_returns_no_matches(self):
        """Empty needle should return no matches."""
        from fortifyroot._internal.safety.engine import _find_literal_matches

        matches = list(_find_literal_matches("some text", "", False))
        assert matches == []

    def test_special_regex_chars_in_needle_are_escaped(self):
        """Needles with regex special chars should be treated as literals."""
        from fortifyroot._internal.safety.engine import _find_literal_matches

        matches = list(_find_literal_matches("a.b a*b a+b", "a.b", False))
        assert len(matches) == 1
        assert matches[0] == (0, 3)

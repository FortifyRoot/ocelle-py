"""Tests for streaming safety holdback evaluation."""

from types import SimpleNamespace
from unittest import mock

from fortifyroot._internal.safety import streaming as safety_streaming
from fortifyroot._internal.safety.engine import compile_snapshot
from fortifyroot._internal.safety.models import (
    ConfigProfile,
    RegexMatcher,
    SafetyConfig,
    SafetyRule,
)
from fortifyroot._internal.safety.streaming import CompletionSafetyStream
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyDecision,
)


def _snapshot(*, action: str = "MASK"):
    return compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-stream",
            version=1,
            etag="etag-stream",
            safety=SafetyConfig(
                enabled=True,
                default_action="ALLOW",
                rules=(
                    SafetyRule(
                        name="email",
                        category="PII",
                        severity="HIGH",
                        action=action,
                        enabled=True,
                        matcher=RegexMatcher(pattern=r"[a-z]+@[a-z]+\.com"),
                    ),
                ),
            ),
        )
    )


def test_stream_completion_masks_cross_chunk_match_on_flush():
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=128)

    assert stream.process_chunk("reach ") is None
    assert stream.process_chunk("me at abc@") is None
    assert stream.process_chunk("gmail.com") is None

    flushed = stream.flush()
    assert flushed is not None
    assert flushed.text == "reach me at [PII.email]"
    assert flushed.overall_action == SafetyDecision.MASK.value
    assert len(flushed.findings) == 1
    assert flushed.findings[0].start == 12
    assert flushed.findings[0].end == 25


def test_stream_completion_releases_prefix_once_holdback_is_exceeded():
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)

    assert stream.process_chunk("abc@") is None
    assert stream.process_chunk("gmail.com") is None

    released = stream.process_chunk(" hello")
    assert released is not None
    assert released.text == "[PII.email] h"
    assert len(released.findings) == 1
    assert released.findings[0].start == 0
    assert released.findings[0].end == 13

    flushed = stream.flush()
    assert flushed is not None
    assert flushed.text == "ello"
    assert flushed.findings == ()


def test_stream_completion_reports_allow_matches_without_masking():
    stream = CompletionSafetyStream(snapshot=_snapshot(action="ALLOW"), holdback_chars=2)

    assert stream.process_chunk("ab") is None
    assert stream.process_chunk("c@gmail.com!") is None

    flushed = stream.flush()
    assert flushed is not None
    assert flushed.text == "abc@gmail.com!"
    assert len(flushed.findings) == 1
    assert flushed.findings[0].action == SafetyDecision.ALLOW.value


def test_stream_completion_handles_empty_inputs_and_empty_flush():
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=8)

    assert stream.process_chunk("") is None
    assert stream.flush() is None


def test_stream_completion_caps_pending_growth_for_pathological_matches():
    stream = CompletionSafetyStream(
        snapshot=compile_snapshot(
            ConfigProfile(
                config_profile_id="cfg-stream-cap",
                version=1,
                etag="etag-stream-cap",
                safety=SafetyConfig(
                    enabled=True,
                    default_action="ALLOW",
                    rules=(
                        SafetyRule(
                            name="catch_all",
                            category="SECRET",
                            severity="HIGH",
                            action="MASK",
                            enabled=True,
                            matcher=RegexMatcher(pattern=r".+"),
                        ),
                    ),
                ),
            )
        ),
        holdback_chars=2,
        max_pending_chars=4,
    )

    assert stream.process_chunk("ab") is None
    assert stream.process_chunk("cd") is None

    released = stream.process_chunk("ef")
    assert released is not None
    assert released.text == "[SECRET.catch_all]"
    assert released.overall_action == SafetyDecision.MASK.value
    assert len(stream._pending_text) == 4

    flushed = stream.flush()
    assert flushed is not None
    assert flushed.text == "[SECRET.catch_all]"


def test_stream_completion_records_force_finalization_metric():
    mock_add = mock.Mock()
    counter = SimpleNamespace(add=mock_add)
    original_counter = safety_streaming._FORCE_FINALIZATIONS_COUNTER
    safety_streaming._FORCE_FINALIZATIONS_COUNTER = counter
    try:
        stream = CompletionSafetyStream(
            snapshot=compile_snapshot(
                ConfigProfile(
                    config_profile_id="cfg-stream-metric",
                    version=1,
                    etag="etag-stream-metric",
                    safety=SafetyConfig(
                        enabled=True,
                        default_action="ALLOW",
                        rules=(
                            SafetyRule(
                                name="catch_all",
                                category="SECRET",
                                severity="HIGH",
                                action="MASK",
                                enabled=True,
                                matcher=RegexMatcher(pattern=r".+"),
                            ),
                        ),
                    ),
                )
            ),
            holdback_chars=2,
            max_pending_chars=4,
        )

        assert stream.process_chunk("ab") is None
        assert stream.process_chunk("cd") is None

        released = stream.process_chunk("ef")
        assert released is not None
    finally:
        safety_streaming._FORCE_FINALIZATIONS_COUNTER = original_counter

    mock_add.assert_called_once_with(
        1,
        attributes={"fortifyroot.safety.pending_cap_chars": "4"},
    )

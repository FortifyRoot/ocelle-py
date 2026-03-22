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


def test_get_pending_text_returns_buffered_content():
    """Cover line 89: get_pending_text() accessor."""
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=128)

    assert stream.get_pending_text() == ""
    stream.process_chunk("hello ")
    assert stream.get_pending_text() == "hello "
    stream.process_chunk("world")
    assert stream.get_pending_text() == "hello world"

    stream.flush()
    assert stream.get_pending_text() == ""


def test_release_returns_none_when_boundary_is_zero():
    """Cover line 99: _release returns None for release_boundary <= 0."""
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)
    stream._pending_text = "abc"

    result = stream._release(0, [])
    assert result is None

    result = stream._release(-1, [])
    assert result is None

    # Pending text should be untouched since _release bailed out early
    assert stream._pending_text == "abc"


def test_release_returns_none_when_result_text_is_empty():
    """Cover line 134: defensive guard in _release when masked_release
    and finalized_absolute are both empty.

    Line 134 is a defensive guard that is not reachable through normal
    code paths (release_text is always non-empty when release_boundary > 0
    and _pending_text is truthy). We use a string subclass to simulate
    the edge case where slicing produces an empty string.
    """
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)

    class EmptySliceStr(str):
        """A string that is truthy but produces empty string when sliced."""

        def __getitem__(self, key):
            return ""

    stream._pending_text = EmptySliceStr("notempty")
    stream._pending_offset = 0
    result = stream._release(1, [])
    assert result is None


def test_evaluate_text_returns_empty_for_disabled_snapshot():
    """Cover line 144: _evaluate_text returns [] when snapshot is disabled."""
    disabled_snapshot = compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-disabled",
            version=1,
            etag="etag-disabled",
            safety=SafetyConfig(
                enabled=False,
                default_action="ALLOW",
                rules=(),
            ),
        )
    )
    stream = CompletionSafetyStream(snapshot=disabled_snapshot, holdback_chars=4)

    # _evaluate_text should return [] for disabled snapshot even with non-empty text
    assert stream._evaluate_text("some text with abc@gmail.com") == []


def test_evaluate_text_returns_empty_for_empty_text_with_enabled_snapshot():
    """Cover line 144: _evaluate_text returns [] for empty text string."""
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)
    assert stream._evaluate_text("") == []


def test_finalize_local_findings_skips_non_overlapping_finding_beyond_boundary():
    """Cover branch 178->174: in _finalize_local_findings with force_finalize=True,
    a finding whose start >= release_boundary is skipped (not truncated)."""
    from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
        SafetyFinding,
    )

    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)

    # Finding that starts at or beyond the release boundary:
    # start=5, end=10, release_boundary=5 => start is NOT < release_boundary
    # so the overlap condition (start < boundary AND end > boundary) is False
    # => finding is skipped, loop continues back to line 174
    finding_beyond = SafetyFinding(
        category="PII",
        severity="HIGH",
        action=SafetyDecision.MASK.value,
        rule_name="email",
        start=5,
        end=10,
    )

    result = stream._finalize_local_findings(
        [finding_beyond],
        release_boundary=5,
        force_finalize=True,
    )
    assert result == ()

    # Also test with a finding entirely beyond the boundary
    finding_far_beyond = SafetyFinding(
        category="PII",
        severity="HIGH",
        action=SafetyDecision.MASK.value,
        rule_name="email",
        start=8,
        end=15,
    )

    result = stream._finalize_local_findings(
        [finding_far_beyond],
        release_boundary=5,
        force_finalize=True,
    )
    assert result == ()


# ---- D-22: O(n^2) streaming release boundary fix ----


def test_resolve_release_boundary_uses_max_end_optimization():
    """D-22: _resolve_release_boundary should use max(f.end) instead of iterative loop."""
    from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
        SafetyFinding,
    )

    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)
    stream._pending_text = "abcdefghijklmnop"  # 16 chars

    # Release boundary = 16 - 4 = 12
    # Finding spans [5, 14), so end > release_boundary
    # The boundary should be pulled back to finding.start = 5
    findings = [
        SafetyFinding(
            category="PII",
            severity="HIGH",
            action=SafetyDecision.MASK.value,
            rule_name="email",
            start=5,
            end=14,
        ),
    ]

    boundary = stream._resolve_release_boundary(findings)
    assert boundary == 5


def test_resolve_release_boundary_no_findings_crossing_boundary():
    """D-22: When no findings cross the boundary, release_boundary stays at text - holdback."""
    from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
        SafetyFinding,
    )

    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)
    stream._pending_text = "abcdefghijklmnop"  # 16 chars

    # Finding entirely before the boundary (end=5 <= 12)
    findings = [
        SafetyFinding(
            category="PII",
            severity="HIGH",
            action=SafetyDecision.MASK.value,
            rule_name="email",
            start=0,
            end=5,
        ),
    ]

    boundary = stream._resolve_release_boundary(findings)
    assert boundary == 12


def test_resolve_release_boundary_multiple_findings_crossing():
    """D-22: When multiple findings cross the boundary, use earliest start."""
    from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
        SafetyFinding,
    )

    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)
    stream._pending_text = "abcdefghijklmnop"  # 16 chars

    # Two findings crossing the boundary (12):
    # Finding 1: [3, 15) - start=3
    # Finding 2: [8, 14) - start=8
    # Should pick min(3, 8) = 3
    findings = [
        SafetyFinding(
            category="PII",
            severity="HIGH",
            action=SafetyDecision.MASK.value,
            rule_name="email1",
            start=3,
            end=15,
        ),
        SafetyFinding(
            category="PII",
            severity="HIGH",
            action=SafetyDecision.MASK.value,
            rule_name="email2",
            start=8,
            end=14,
        ),
    ]

    boundary = stream._resolve_release_boundary(findings)
    assert boundary == 3


def test_resolve_release_boundary_empty_findings():
    """D-22: With no findings, release_boundary = text - holdback."""
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)
    stream._pending_text = "abcdefghijklmnop"  # 16 chars

    boundary = stream._resolve_release_boundary([])
    assert boundary == 12


def test_streaming_end_to_end_with_optimized_boundary():
    """D-22: End-to-end test to verify the optimized boundary produces correct results."""
    stream = CompletionSafetyStream(snapshot=_snapshot(), holdback_chars=4)

    # "hello " is safe prefix released immediately, "abc@" held back in pending
    result1 = stream.process_chunk("hello abc@")
    assert result1 is not None
    assert result1.text == "hello "

    # "abc@gmail.com" completes the email match; masked text released
    result2 = stream.process_chunk("gmail.com bye")
    assert result2 is not None
    assert "[PII.email]" in result2.text

    flushed = stream.flush()
    assert flushed is not None

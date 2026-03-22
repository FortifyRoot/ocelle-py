"""Streaming completion safety evaluation with bounded holdback."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from opentelemetry.metrics import get_meter

from fortifyroot._internal.safety.engine import (
    CompiledSafetySnapshot,
    _apply_masks,
    _evaluate_rule,
    _resolve_overall_action,
)
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyDecision,
    SafetyFinding,
    SafetyResult,
)

logger = logging.getLogger(__name__)
_METER = get_meter("fortifyroot.safety")
_FORCE_FINALIZATIONS_COUNTER = _METER.create_counter(
    "fortifyroot.safety.streaming_force_finalizations",
    description="Number of streaming safety force-finalizations due to pending-buffer caps.",
)

MIN_PENDING_CAP_CHARS = 4096
MAX_PENDING_MULTIPLIER = 16


@dataclass(slots=True)
class CompletionSafetyStream:
    """Streaming completion evaluator with bounded holdback and pending-text cap."""

    snapshot: CompiledSafetySnapshot
    holdback_chars: int
    max_pending_chars: int | None = None
    _pending_text: str = ""
    _pending_offset: int = 0
    _warned_pending_cap: bool = False

    def __post_init__(self) -> None:
        if self.max_pending_chars is None:
            self.max_pending_chars = max(
                self.holdback_chars * MAX_PENDING_MULTIPLIER,
                MIN_PENDING_CAP_CHARS,
            )
        self.max_pending_chars = max(self.max_pending_chars, self.holdback_chars)

    def process_chunk(self, text: str) -> SafetyResult | None:
        if not text:
            return None

        self._pending_text += text
        findings = self._evaluate_text(self._pending_text)
        release_boundary = self._resolve_release_boundary(findings)
        force_finalize = False
        forced_boundary = self._resolve_forced_release_boundary()
        if forced_boundary > release_boundary:
            release_boundary = forced_boundary
            force_finalize = True
        if release_boundary <= 0:
            return None
        if force_finalize and not self._warned_pending_cap:
            logger.warning(
                "Streaming safety pending buffer exceeded cap (%d chars); "
                "force-finalizing overlapping findings",
                self.max_pending_chars,
            )
            self._warned_pending_cap = True
        if force_finalize:
            _FORCE_FINALIZATIONS_COUNTER.add(
                1,
                attributes={"fortifyroot.safety.pending_cap_chars": str(self.max_pending_chars)},
            )
        return self._release(release_boundary, findings, force_finalize=force_finalize)

    def flush(self) -> SafetyResult | None:
        if not self._pending_text:
            return None
        return self._release(
            len(self._pending_text),
            self._evaluate_text(self._pending_text),
        )

    def get_pending_text(self) -> str:
        return self._pending_text

    def _release(
        self,
        release_boundary: int,
        findings: list[SafetyFinding],
        *,
        force_finalize: bool = False,
    ) -> SafetyResult | None:
        if not self._pending_text or release_boundary <= 0:
            return None

        pending_text = self._pending_text
        pending_offset = self._pending_offset
        release_text = pending_text[:release_boundary]
        trailing_text = pending_text[release_boundary:]

        finalized_local = self._finalize_local_findings(
            findings,
            release_boundary,
            force_finalize=force_finalize,
        )

        masked_release = release_text
        finalized_absolute: tuple[SafetyFinding, ...] = ()
        overall_action = SafetyDecision.ALLOW.value
        if finalized_local:
            masked_release = _apply_masks(release_text, finalized_local)
            finalized_absolute = tuple(
                SafetyFinding(
                    category=finding.category,
                    severity=finding.severity,
                    action=finding.action,
                    rule_name=finding.rule_name,
                    start=finding.start + pending_offset,
                    end=finding.end + pending_offset,
                )
                for finding in finalized_local
            )
            overall_action = _resolve_overall_action(finalized_local)

        self._pending_text = trailing_text
        self._pending_offset = pending_offset + release_boundary

        if not masked_release and not finalized_absolute:
            return None

        return SafetyResult(
            text=masked_release,
            findings=finalized_absolute,
            overall_action=overall_action,
        )

    def _evaluate_text(self, text: str) -> list[SafetyFinding]:
        if not self.snapshot.enabled or not text:
            return []

        findings: list[SafetyFinding] = []
        for rule in self.snapshot.rules:
            findings.extend(_evaluate_rule(rule, text))
        return findings

    def _resolve_release_boundary(self, findings: list[SafetyFinding]) -> int:
        release_boundary = len(self._pending_text) - self.holdback_chars
        if release_boundary <= 0:
            return 0

        max_finding_end = max((f.end for f in findings), default=0)
        if max_finding_end > release_boundary:
            release_boundary = min(
                (f.start for f in findings if f.end > release_boundary),
                default=release_boundary,
            )
        release_boundary = max(release_boundary, 0)
        return release_boundary

    def _resolve_forced_release_boundary(self) -> int:
        if len(self._pending_text) <= self.max_pending_chars:
            return 0
        return len(self._pending_text) - self.max_pending_chars

    def _finalize_local_findings(
        self,
        findings: list[SafetyFinding],
        release_boundary: int,
        *,
        force_finalize: bool,
    ) -> tuple[SafetyFinding, ...]:
        finalized: list[SafetyFinding] = []
        for finding in findings:
            if finding.end <= release_boundary:
                finalized.append(finding)
                continue
            if (
                force_finalize
                and finding.start < release_boundary
                and finding.end > release_boundary
            ):
                finalized.append(
                    SafetyFinding(
                        category=finding.category,
                        severity=finding.severity,
                        action=finding.action,
                        rule_name=finding.rule_name,
                        start=finding.start,
                        end=release_boundary,
                    )
                )
        return tuple(finalized)

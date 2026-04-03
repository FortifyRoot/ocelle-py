"""
Shared safety handler module for SDK provider cassette tests (T5, T6, and beyond).

Provides reusable safety scan/mask/handler functions identical to the fork pattern
(fr-openllmetry-py T2-T4) so all SDK provider test suites use consistent rules:

  - RegEx:  PII.email, PCI.credit_card
  - List:   PII.competitor_org
  - UDF:    custom_compliance.project-phoenix, custom_compliance.operation-atlas

Usage in test files:
    from tests.providers.safety_handlers import (
        set_safety_action,
        register_all_handlers,
        clear_all_handlers,
        SAFETY_ACTION_MASK,
        SAFETY_ACTION_ALLOW,
    )

North-star: This is a NEW file (FR-owned). Zero delta on _vendor files.
"""

from __future__ import annotations

import re

from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyFinding,
    SafetyLocation,
    SafetyResult,
    clear_safety_handlers,
    register_completion_safety_handler,
    register_prompt_safety_handler,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SAFETY_ACTION_MASK = "MASK"
SAFETY_ACTION_ALLOW = "ALLOW"

# ---------------------------------------------------------------------------
# Safety rule definitions (mirror what real SDK rules would do)
# ---------------------------------------------------------------------------

# RegEx patterns
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

# List of competitor org names (case-insensitive)
_COMPETITOR_ORGS = ["acme corp", "globex industries", "initech", "umbrella inc"]

# UDF: detects two fictional project codenames
_PROJECT_CODENAMES = ["project-phoenix", "operation-atlas"]

# Module-level action setting (switched by set_safety_action)
_safety_action = SAFETY_ACTION_MASK


# ---------------------------------------------------------------------------
# Action toggle
# ---------------------------------------------------------------------------


def set_safety_action(action: str) -> None:
    """Set the module-level safety action (MASK or ALLOW)."""
    global _safety_action
    _safety_action = action


def get_safety_action() -> str:
    """Get the current module-level safety action."""
    return _safety_action


# ---------------------------------------------------------------------------
# Core scan / mask helpers
# ---------------------------------------------------------------------------


def _build_findings_and_mask(
    text: str, findings_list: list[SafetyFinding], action: str = "MASK"
) -> SafetyResult | None:
    """Apply all collected findings to produce masked (or allowed) text."""
    if not findings_list:
        return None
    if action == "MASK":
        masked = text
        for f in sorted(findings_list, key=lambda x: x.start, reverse=True):
            masked = masked[: f.start] + f"[{f.rule_name}]" + masked[f.end :]
        return SafetyResult(
            text=masked,
            overall_action="MASK",
            findings=findings_list,
        )
    # ALLOW: text unchanged, findings still recorded
    return SafetyResult(
        text=text,
        overall_action="ALLOW",
        findings=findings_list,
    )


def _scan_text(text: str, location: SafetyLocation) -> list[SafetyFinding]:
    """Run all safety rule types against text, return findings."""
    if not isinstance(text, str) or not text:
        return []

    action = _safety_action
    findings: list[SafetyFinding] = []

    # --- RegEx: PCI.credit_card ---
    for m in _CREDIT_CARD_RE.finditer(text):
        findings.append(
            SafetyFinding(
                category="PCI",
                severity="HIGH",
                action=action,
                rule_name="PCI.credit_card",
                start=m.start(),
                end=m.end(),
            )
        )

    # --- RegEx: PII.email ---
    for m in _EMAIL_RE.finditer(text):
        findings.append(
            SafetyFinding(
                category="PII",
                severity="MEDIUM",
                action=action,
                rule_name="PII.email",
                start=m.start(),
                end=m.end(),
            )
        )

    # --- List: PII.competitor_org ---
    text_lower = text.lower()
    for org in _COMPETITOR_ORGS:
        idx = text_lower.find(org)
        while idx != -1:
            findings.append(
                SafetyFinding(
                    category="PII",
                    severity="LOW",
                    action=action,
                    rule_name="PII.competitor_org",
                    start=idx,
                    end=idx + len(org),
                )
            )
            idx = text_lower.find(org, idx + len(org))

    # --- UDF: custom_compliance.project_codename ---
    for codename in _PROJECT_CODENAMES:
        idx = text_lower.find(codename)
        while idx != -1:
            findings.append(
                SafetyFinding(
                    category="COMPLIANCE",
                    severity="HIGH",
                    action=action,
                    rule_name=f"custom_compliance.{codename}",
                    start=idx,
                    end=idx + len(codename),
                )
            )
            idx = text_lower.find(codename, idx + len(codename))

    return findings


# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------


def prompt_handler(context):
    """Prompt safety handler covering RegEx, List, and UDF rules."""
    if context.location != SafetyLocation.PROMPT:
        return None
    findings = _scan_text(context.text, SafetyLocation.PROMPT)
    return _build_findings_and_mask(context.text, findings, action=_safety_action)


def completion_handler(context):
    """Completion safety handler covering RegEx, List, and UDF rules."""
    if context.location != SafetyLocation.COMPLETION:
        return None
    findings = _scan_text(context.text, SafetyLocation.COMPLETION)
    return _build_findings_and_mask(context.text, findings, action=_safety_action)


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------


def register_all_handlers() -> None:
    """Clear existing handlers and register prompt + completion handlers."""
    clear_safety_handlers()
    register_prompt_safety_handler(prompt_handler)
    register_completion_safety_handler(completion_handler)


def clear_all_handlers() -> None:
    """Clear all registered safety handlers and reset action to MASK."""
    global _safety_action
    clear_safety_handlers()
    _safety_action = SAFETY_ACTION_MASK

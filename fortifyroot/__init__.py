"""
FortifyRoot SDK
LLM observability + safety guardrails.

Usage:
    import fortifyroot

    fortifyroot.enforce(
        config_path="config.yaml",
        policies=["PII", "PCI", "SECRET", "JAILBREAK"],
    )

    # All LLM calls are now protected automatically
"""

__version__ = "0.1.0"

from fortifyroot.sdk import (
    observe,
    enforce,
    set_context,
    get_context,
    clear_context,
    scoped_context,
    FortifyRootBlocked,
)

__all__ = [
    "__version__",
    "observe",
    "enforce",
    "set_context",
    "get_context",
    "clear_context",
    "scoped_context",
    "FortifyRootBlocked",
]

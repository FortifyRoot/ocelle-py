"""Convenience import alias for FortifyRoot Ocelle.

The canonical import is:

    import fortifyroot.ocelle as ocelle

This top-level module re-exports the same public API for users who install the
official package and prefer ``import ocelle``.
"""

from fortifyroot.ocelle import (
    FortifyRootConfig,
    Instruments,
    TextSafetyDetector,
    TextSafetyMatch,
    __version__,
    agent,
    configure,
    init,
    set_association_properties,
    task,
    tool,
    workflow,
)

OcelleConfig = FortifyRootConfig

__all__ = [
    "init",
    "set_association_properties",
    "configure",
    "OcelleConfig",
    "FortifyRootConfig",
    "task",
    "workflow",
    "agent",
    "tool",
    "Instruments",
    "TextSafetyDetector",
    "TextSafetyMatch",
    "__version__",
]

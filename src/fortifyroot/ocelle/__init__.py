"""FortifyRoot Ocelle public API.

This module is the canonical product import surface:

    import fortifyroot.ocelle as ocelle

The implementation currently lives in the parent ``fortifyroot`` package so
internal vendored import rewrites and telemetry contracts remain stable.
"""

from fortifyroot import (
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

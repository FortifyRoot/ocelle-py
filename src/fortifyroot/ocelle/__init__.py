"""FortifyRoot Ocelle public API.

This module is the canonical product import surface:

    import fortifyroot.ocelle as ocelle

The implementation currently lives in the parent ``fortifyroot`` package so
internal vendored import rewrites and telemetry contracts remain stable.
"""

# Apply environment variable mapping BEFORE importing anything from _vendor.
# This ensures FORTIFYROOT_* env vars are mapped to TRACELOOP_* equivalents
# before any vendor modules read them at import time.
from fortifyroot._internal.env_mapping import apply_env_var_mapping

apply_env_var_mapping()

from fortifyroot.core import (
    FortifyRootConfig,
    configure,
    init,
    set_association_properties,
)
from fortifyroot.decorators import agent, task, tool, workflow
from fortifyroot.instruments import Instruments
from fortifyroot.safety import TextSafetyDetector, TextSafetyMatch
from fortifyroot.version import __version__

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

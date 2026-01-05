"""Environment variable mapping from FORTIFYROOT_* to TRACELOOP_*."""

import os
from typing import Dict

# Mapping of FortifyRoot environment variables to Traceloop equivalents
ENV_VAR_MAPPING: Dict[str, str] = {
    # Core configuration
    "FORTIFYROOT_BASE_URL": "TRACELOOP_BASE_URL",
    "FORTIFYROOT_API_KEY": "TRACELOOP_API_KEY",
    "FORTIFYROOT_HEADERS": "TRACELOOP_HEADERS",
    # Tracing configuration
    "FORTIFYROOT_TRACING_ENABLED": "TRACELOOP_TRACING_ENABLED",
    "FORTIFYROOT_TRACE_CONTENT": "TRACELOOP_TRACE_CONTENT",
    "FORTIFYROOT_SUPPRESS_WARNINGS": "TRACELOOP_SUPPRESS_WARNINGS",
    # Metrics configuration
    "FORTIFYROOT_METRICS_ENABLED": "TRACELOOP_METRICS_ENABLED",
    "FORTIFYROOT_METRICS_ENDPOINT": "TRACELOOP_METRICS_ENDPOINT",
    "FORTIFYROOT_METRICS_HEADERS": "TRACELOOP_METRICS_HEADERS",
    # Logging configuration
    "FORTIFYROOT_LOGGING_ENABLED": "TRACELOOP_LOGGING_ENABLED",
    "FORTIFYROOT_LOGGING_ENDPOINT": "TRACELOOP_LOGGING_ENDPOINT",
    "FORTIFYROOT_LOGGING_HEADERS": "TRACELOOP_LOGGING_HEADERS",
}


def apply_env_var_mapping() -> None:
    """
    Map FORTIFYROOT_* environment variables to their TRACELOOP_* equivalents.

    This function should be called at package import time, before any
    traceloop-sdk modules are imported, to ensure that environment variables
    are properly set for the underlying SDK.

    Note: This sets/unsets TRACELOOP_* vars based on whether corresponding FORTIFYROOT_*
    vars are set/unset.
    """
    for fr_key, tl_key in ENV_VAR_MAPPING.items():
        fr_value = os.environ.get(fr_key)
        tl_value = os.environ.get(tl_key)
        if fr_value:
            os.environ[tl_key] = fr_value
        elif tl_value:
            os.environ.pop(tl_key)

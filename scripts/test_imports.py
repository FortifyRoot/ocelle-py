#!/usr/bin/env python3
"""
Test script to verify all FortifyRoot Ocelle SDK imports work correctly.

Run this AFTER pip install -e . to verify everything is set up correctly.

Usage:
    python scripts/test_imports.py
"""

import sys

def test_imports():
    """Test all critical imports."""
    errors = []
    
    print("=" * 60)
    print("FortifyRoot Ocelle SDK Import Test")
    print("=" * 60)
    print(f"Python: {sys.executable}")
    print(f"Version: {sys.version}")
    print()
    
    # Test 1: Core OpenTelemetry packages (from PyPI)
    print("Testing Core OpenTelemetry packages...")
    
    try:
        from opentelemetry import trace
        print("  ✓ opentelemetry.trace")
    except ImportError as e:
        errors.append(f"opentelemetry.trace: {e}")
        print(f"  ✗ opentelemetry.trace: {e}")
    
    try:
        from opentelemetry.context import Context
        print("  ✓ opentelemetry.context.Context")
    except ImportError as e:
        errors.append(f"opentelemetry.context: {e}")
        print(f"  ✗ opentelemetry.context: {e}")
    
    try:
        from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor
        print("  ✓ opentelemetry.sdk.trace (ReadableSpan, Span, SpanProcessor)")
    except ImportError as e:
        errors.append(f"opentelemetry.sdk.trace: {e}")
        print(f"  ✗ opentelemetry.sdk.trace: {e}")
    
    try:
        from opentelemetry.trace import get_tracer, SpanKind
        print("  ✓ opentelemetry.trace (get_tracer, SpanKind)")
    except ImportError as e:
        errors.append(f"opentelemetry.trace: {e}")
        print(f"  ✗ opentelemetry.trace: {e}")
    
    try:
        from opentelemetry.trace.status import Status, StatusCode
        print("  ✓ opentelemetry.trace.status (Status, StatusCode)")
    except ImportError as e:
        errors.append(f"opentelemetry.trace.status: {e}")
        print(f"  ✗ opentelemetry.trace.status: {e}")
    
    try:
        from opentelemetry.trace.propagation import set_span_in_context
        print("  ✓ opentelemetry.trace.propagation")
    except ImportError as e:
        errors.append(f"opentelemetry.trace.propagation: {e}")
        print(f"  ✗ opentelemetry.trace.propagation: {e}")
    
    try:
        from opentelemetry.metrics import get_meter
        print("  ✓ opentelemetry.metrics.get_meter")
    except ImportError as e:
        errors.append(f"opentelemetry.metrics: {e}")
        print(f"  ✗ opentelemetry.metrics: {e}")
    
    try:
        from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
        print("  ✓ opentelemetry.instrumentation.instrumentor.BaseInstrumentor")
    except ImportError as e:
        errors.append(f"opentelemetry.instrumentation.instrumentor: {e}")
        print(f"  ✗ opentelemetry.instrumentation.instrumentor: {e}")
    
    try:
        from opentelemetry.instrumentation.utils import unwrap
        print("  ✓ opentelemetry.instrumentation.utils.unwrap")
    except ImportError as e:
        errors.append(f"opentelemetry.instrumentation.utils: {e}")
        print(f"  ✗ opentelemetry.instrumentation.utils: {e}")
    
    # Note: opentelemetry.util.types may not exist in all versions
    try:
        from opentelemetry.util.types import Attributes
        print("  ✓ opentelemetry.util.types.Attributes")
    except ImportError:
        # Try alternative import
        try:
            from typing import Mapping
            Attributes = Mapping[str, any]
            print("  ⚠ opentelemetry.util.types.Attributes (using typing.Mapping fallback)")
        except Exception as e:
            errors.append(f"opentelemetry.util.types: {e}")
            print(f"  ✗ opentelemetry.util.types: {e}")
    
    # Incubating semconv (may not be available)
    try:
        from opentelemetry.semconv._incubating.attributes import gen_ai_attributes
        print("  ✓ opentelemetry.semconv._incubating.attributes")
    except ImportError:
        print("  ⚠ opentelemetry.semconv._incubating.attributes (optional, may not exist)")
    
    print()
    
    # Test 2: Third-party dependencies
    print("Testing third-party dependencies...")
    
    try:
        import pydantic
        print(f"  ✓ pydantic ({pydantic.VERSION})")
    except ImportError as e:
        errors.append(f"pydantic: {e}")
        print(f"  ✗ pydantic: {e}")
    
    try:
        import wrapt
        print("  ✓ wrapt")
    except ImportError as e:
        errors.append(f"wrapt: {e}")
        print(f"  ✗ wrapt: {e}")
    
    try:
        import colorama
        print("  ✓ colorama")
    except ImportError as e:
        errors.append(f"colorama: {e}")
        print(f"  ✗ colorama: {e}")
    
    try:
        import aiohttp
        print("  ✓ aiohttp")
    except ImportError as e:
        errors.append(f"aiohttp: {e}")
        print(f"  ✗ aiohttp: {e}")
    
    try:
        import jinja2
        print("  ✓ jinja2")
    except ImportError as e:
        errors.append(f"jinja2: {e}")
        print(f"  ✗ jinja2: {e}")
    
    print()
    
    # Test 3: Vendored packages
    print("Testing vendored packages...")
    
    try:
        from fortifyroot._vendor.tracer.sdk import Traceloop
        print("  ✓ fortifyroot._vendor.tracer.sdk.Traceloop")
    except ImportError as e:
        errors.append(f"vendored tracer SDK: {e}")
        print(f"  ✗ fortifyroot._vendor.tracer.sdk: {e}")
    
    try:
        from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes
        print("  ✓ fortifyroot._vendor.opentelemetry.semconv_ai.SpanAttributes")
    except ImportError as e:
        errors.append(f"vendored semconv_ai: {e}")
        print(f"  ✗ fortifyroot._vendor.opentelemetry.semconv_ai: {e}")
    
    try:
        from fortifyroot._vendor.opentelemetry.instrumentation.openai import OpenAIInstrumentor
        print("  ✓ fortifyroot._vendor.opentelemetry.instrumentation.openai")
    except ImportError as e:
        errors.append(f"vendored openai instrumentation: {e}")
        print(f"  ✗ fortifyroot._vendor.opentelemetry.instrumentation.openai: {e}")

    try:
        from fortifyroot._vendor.opentelemetry.instrumentation.litellm import LiteLLMInstrumentor
        print("  ✓ fortifyroot._vendor.opentelemetry.instrumentation.litellm")
    except ImportError as e:
        errors.append(f"vendored litellm instrumentation: {e}")
        print(f"  ✗ fortifyroot._vendor.opentelemetry.instrumentation.litellm: {e}")
    
    print()
    
    # Test 4: FortifyRoot Ocelle public API
    print("Testing FortifyRoot Ocelle public API...")
    
    try:
        import fortifyroot.ocelle as ocelle
        print("  ✓ import fortifyroot.ocelle as ocelle")
    except ImportError as e:
        errors.append(f"fortifyroot.ocelle: {e}")
        print(f"  ✗ import fortifyroot.ocelle: {e}")
    
    try:
        import ocelle
        print("  ✓ import ocelle")
    except ImportError as e:
        errors.append(f"ocelle: {e}")
        print(f"  ✗ import ocelle: {e}")
    
    try:
        import fortifyroot
        assert not hasattr(fortifyroot, "init")
        assert not hasattr(fortifyroot, "configure")
        print("  ✓ import fortifyroot namespace without legacy public API")
    except ImportError as e:
        errors.append(f"fortifyroot: {e}")
        print(f"  ✗ import fortifyroot: {e}")
    except AssertionError as e:
        errors.append(f"fortifyroot legacy API still exposed: {e}")
        print(f"  ✗ fortifyroot namespace exposes legacy public API: {e}")
    
    try:
        from fortifyroot.ocelle import init, Instruments, task, workflow
        print("  ✓ fortifyroot.ocelle init, Instruments, task, workflow")
    except ImportError as e:
        errors.append(f"fortifyroot.ocelle API: {e}")
        print(f"  ✗ fortifyroot.ocelle public API: {e}")
    
    print()
    print("=" * 60)
    
    if errors:
        print(f"FAILED: {len(errors)} import(s) failed")
        print()
        print("Missing packages. Run:")
        print("  pip install -e .")
        print()
        return 1
    else:
        print("SUCCESS: All imports working!")
        return 0


if __name__ == "__main__":
    sys.exit(test_imports())

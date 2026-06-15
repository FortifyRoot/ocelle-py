"""
FortifyRoot Ocelle SDK for LLM Observability.

FortifyRoot provides automatic instrumentation and observability for LLM applications.
Simply call `ocelle.init()` to start capturing traces from supported LLM libraries
including OpenAI, Anthropic, Google GenAI, Bedrock, LangChain, LiteLLM, and LlamaIndex.

Example:
    Basic usage::

        import fortifyroot.ocelle as ocelle

        ocelle.init(
            app_name="my-llm-app",
            api_key="fr-xxx",
        )

        # Your LLM calls are now automatically traced
        import openai
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello!"}]
        )

    Using decorators to trace custom functions::

        from fortifyroot.ocelle import workflow, task

        @workflow(name="my_pipeline")
        def run_pipeline(input_text):
            result = process_step(input_text)
            return result

        @task(name="process_step")
        def process_step(text):
            # Your processing logic
            return processed_text

    Using the fluent configuration API::

        ocelle.configure() \\
            .app_name("my-app") \\
            .api_key("fr-xxx") \\
            .trace_content(False) \\
            .init()
"""

# Apply environment variable mapping BEFORE importing anything from _vendor
# This ensures FORTIFYROOT_* env vars are mapped to TRACELOOP_* equivalents
# before any vendor modules read them at import time.
from fortifyroot._internal.env_mapping import apply_env_var_mapping

apply_env_var_mapping()

# Now import and expose public API
from fortifyroot.core import (
    init,
    set_association_properties,
    configure,
    FortifyRootConfig,
)
from fortifyroot.decorators import agent, task, tool, workflow
from fortifyroot.instruments import Instruments
from fortifyroot.safety import TextSafetyDetector, TextSafetyMatch
from fortifyroot.version import __version__

__all__ = [
    # Core functions
    "init",
    "set_association_properties",
    # Fluent API
    "configure",
    "FortifyRootConfig",
    # Decorators
    "task",
    "workflow",
    "agent",
    "tool",
    # Enums
    "Instruments",
    "TextSafetyDetector",
    "TextSafetyMatch",
    # Version
    "__version__",
]

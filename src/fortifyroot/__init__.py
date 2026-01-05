"""
FortifyRoot SDK for LLM Observability.

FortifyRoot provides automatic instrumentation and observability for LLM applications.
Simply call `fortifyroot.init()` to start capturing traces from supported LLM libraries
including OpenAI, Anthropic, LangChain, LlamaIndex, and more.

Example:
    Basic usage::

        import fortifyroot

        fortifyroot.init(
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

        from fortifyroot import workflow, task

        @workflow(name="my_pipeline")
        def run_pipeline(input_text):
            result = process_step(input_text)
            return result

        @task(name="process_step")
        def process_step(text):
            # Your processing logic
            return processed_text

Attribution:
    This SDK is built on top of OpenLLMetry by Traceloop, licensed under Apache 2.0.
    https://github.com/traceloop/openllmetry
"""

# Apply environment variable mapping BEFORE importing anything from traceloop
# This ensures FORTIFYROOT_* env vars are mapped to TRACELOOP_* equivalents
# before any traceloop modules read them at import time.
from fortifyroot._internal.env_mapping import apply_env_var_mapping

apply_env_var_mapping()

# Now import and expose public API
from fortifyroot.core import init, set_association_properties
from fortifyroot.decorators import agent, task, tool, workflow
from fortifyroot.instruments import Instruments
from fortifyroot.version import __version__

__all__ = [
    # Core functions
    "init",
    "set_association_properties",
    # Decorators
    "task",
    "workflow",
    "agent",
    "tool",
    # Enums
    "Instruments",
    # Version
    "__version__",
]

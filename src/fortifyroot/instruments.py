"""Instruments enum for specifying which LLM libraries to instrument.

This module provides the Instruments enum that allows you to selectively
enable or disable auto-instrumentation for specific LLM libraries and frameworks.

Example:
    ::

        from fortifyroot.ocelle import Instruments
        import fortifyroot.ocelle as ocelle

        # Only instrument OpenAI and LangChain
        ocelle.init(
            app_name="my-app",
            api_key="fr-xxx",
            instruments={Instruments.OPENAI, Instruments.LANGCHAIN},
        )

        # Instrument everything except Bedrock
        ocelle.init(
            app_name="my-app",
            api_key="fr-xxx",
            block_instruments={Instruments.BEDROCK},
        )
"""

from enum import Enum
from typing import FrozenSet, Optional, Set

from fortifyroot._vendor.tracer.sdk.instruments import Instruments as _TLInstruments


class Instruments(Enum):
    """
    Enum of supported LLM libraries and frameworks for auto-instrumentation.

    Use this enum with the `instruments` or `block_instruments` parameters
    in `ocelle.init()` to control which libraries are instrumented.

    Categories:
        LLM Providers:
            OPENAI, ANTHROPIC, GOOGLE_GENERATIVEAI, BEDROCK, LITELLM

        Frameworks:
            LANGCHAIN, LLAMA_INDEX
    """

    # LLM Providers
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE_GENERATIVEAI = "google_generativeai"
    BEDROCK = "bedrock"
    LITELLM = "litellm"

    # Frameworks
    LANGCHAIN = "langchain"
    LLAMA_INDEX = "llama_index"


SUPPORTED_INSTRUMENTS: FrozenSet[Instruments] = frozenset(Instruments)


def _convert_to_tl_instruments(
    fr_instruments: Optional[Set[Instruments]],
) -> Optional[Set[_TLInstruments]]:
    """
    Convert FortifyRoot Instruments enum set to Traceloop Instruments enum set.

    Args:
        fr_instruments: Set of FortifyRoot Instruments, or None.

    Returns:
        Set of Traceloop Instruments, or None if input is None.
    """
    if fr_instruments is None:
        return None

    tl_instruments: Set[_TLInstruments] = set()
    for fr_inst in fr_instruments:
        # Convert by matching the string value
        tl_instruments.add(_TLInstruments(fr_inst.value))

    return tl_instruments


__all__ = [
    "Instruments",
    "SUPPORTED_INSTRUMENTS",
]

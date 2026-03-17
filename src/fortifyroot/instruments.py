"""Instruments enum for specifying which LLM libraries to instrument.

This module provides the Instruments enum that allows you to selectively
enable or disable auto-instrumentation for specific LLM libraries and frameworks.

Example:
    ::

        from fortifyroot import Instruments
        import fortifyroot

        # Only instrument OpenAI and LangChain
        fortifyroot.init(
            app_name="my-app",
            api_key="fr-xxx",
            instruments={Instruments.OPENAI, Instruments.LANGCHAIN},
        )

        # Instrument everything except Pinecone
        fortifyroot.init(
            app_name="my-app",
            api_key="fr-xxx",
            block_instruments={Instruments.PINECONE},
        )
"""

from enum import Enum
from typing import Optional, Set

from fortifyroot._vendor.traceloop.sdk.instruments import Instruments as _TLInstruments


class Instruments(Enum):
    """
    Enum of supported LLM libraries and frameworks for auto-instrumentation.

    Use this enum with the `instruments` or `block_instruments` parameters
    in `fortifyroot.init()` to control which libraries are instrumented.

    Categories:
        LLM Providers:
            OPENAI, ANTHROPIC, COHERE, GOOGLE_GENERATIVEAI, MISTRAL, GROQ,
            OLLAMA, BEDROCK, VERTEXAI, REPLICATE, TOGETHER, WATSONX,
            LITELLM,
            ALEPHALPHA, SAGEMAKER, WRITER

        Frameworks:
            LANGCHAIN, LLAMA_INDEX, HAYSTACK, CREWAI, OPENAI_AGENTS, MCP

        Vector Databases:
            PINECONE, CHROMA, MILVUS, QDRANT, WEAVIATE, LANCEDB, MARQO

        Other:
            TRANSFORMERS, REDIS, REQUESTS, URLLIB3, PYMYSQL, AGNO
    """

    # LLM Providers
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    COHERE = "cohere"
    GOOGLE_GENERATIVEAI = "google_generativeai"
    MISTRAL = "mistral"
    GROQ = "groq"
    OLLAMA = "ollama"
    BEDROCK = "bedrock"
    VERTEXAI = "vertexai"
    REPLICATE = "replicate"
    TOGETHER = "together"
    WATSONX = "watsonx"
    LITELLM = "litellm"
    ALEPHALPHA = "alephalpha"
    SAGEMAKER = "sagemaker"
    WRITER = "writer"

    # Frameworks
    LANGCHAIN = "langchain"
    LLAMA_INDEX = "llama_index"
    HAYSTACK = "haystack"
    CREWAI = "crewai"
    OPENAI_AGENTS = "openai_agents"
    MCP = "mcp"
    AGNO = "agno"

    # Vector Databases
    PINECONE = "pinecone"
    CHROMA = "chroma"
    MILVUS = "milvus"
    QDRANT = "qdrant"
    WEAVIATE = "weaviate"
    LANCEDB = "lancedb"
    MARQO = "marqo"

    # Other
    TRANSFORMERS = "transformers"
    REDIS = "redis"
    REQUESTS = "requests"
    URLLIB3 = "urllib3"
    PYMYSQL = "pymysql"


# Internal mapping from FR enum to TL enum
_FR_TO_TL_INSTRUMENTS = {member.value: member.value for member in Instruments}


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
]

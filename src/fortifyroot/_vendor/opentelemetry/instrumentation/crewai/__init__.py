"""OpenTelemetry CrewAI instrumentation"""
from fortifyroot._vendor.opentelemetry.instrumentation.crewai.version import __version__
from fortifyroot._vendor.opentelemetry.instrumentation.crewai.instrumentation import CrewAIInstrumentor

__all__ = ["CrewAIInstrumentor", "__version__"]

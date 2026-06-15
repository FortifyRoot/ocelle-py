"""Public safety detector contracts for FortifyRoot Ocelle SDK."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TextSafetyMatch:
    """A single text match returned by a user-defined detector."""

    name: str
    start: int
    end: int


class TextSafetyDetector(ABC):
    """Base class for Python UDF safety detectors.

    Implementors should inspect the input text and return zero or more
    `TextSafetyMatch` instances. A single detector may return matches for
    multiple sub-patterns in one pass.
    """

    @abstractmethod
    def detect(self, text: str) -> Sequence[TextSafetyMatch]:
        """Return zero or more detected text matches."""


__all__ = ["TextSafetyDetector", "TextSafetyMatch"]

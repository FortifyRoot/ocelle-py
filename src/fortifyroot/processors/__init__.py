"""Span processors for FortifyRoot Ocelle SDK."""

from fortifyroot.processors.attribute_renamer import (
    AttributeRenamingProcessor,
    RenamedSpan,
    create_renamed_span,
    rename_attributes,
)

__all__ = [
    "AttributeRenamingProcessor",
    "RenamedSpan",
    "create_renamed_span",
    "rename_attributes",
]

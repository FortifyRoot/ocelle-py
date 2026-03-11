"""SDK-local safety config models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RegexMatcher:
    pattern: str


@dataclass(frozen=True, slots=True)
class StringListMatcher:
    values: tuple[str, ...]
    ignore_case: bool


@dataclass(frozen=True, slots=True)
class UdfMatcher:
    entry_point: str
    languages: tuple[str, ...]


Matcher = RegexMatcher | StringListMatcher | UdfMatcher


@dataclass(frozen=True, slots=True)
class SafetyRule:
    name: str
    category: str
    severity: str
    action: str | None
    enabled: bool
    matcher: Matcher


@dataclass(frozen=True, slots=True)
class SafetyConfig:
    enabled: bool
    default_action: str
    rules: tuple[SafetyRule, ...]


@dataclass(frozen=True, slots=True)
class ConfigProfile:
    config_profile_id: str
    version: int
    etag: str
    safety: SafetyConfig


@dataclass(frozen=True, slots=True)
class SdkConfigResponse:
    config_profile: ConfigProfile | None
    not_modified: bool

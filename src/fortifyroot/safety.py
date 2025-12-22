"""
FortifyRoot Safety Engine
Rule-based detection and redaction with YAML configuration support.
Supports regex, list, and hybrid detection modes with pluggable validators.
"""

import importlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union

import yaml

logger = logging.getLogger(__name__)


class Action(Enum):
    """Safety action to take on detection."""
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class DetectionMode(Enum):
    """Rule detection mode."""
    REGEX = "regex"
    LIST = "list"
    HYBRID = "hybrid"


@dataclass
class Detection:
    """Represents a detected sensitive content match."""
    rule_name: str      # e.g., "PII.EMAIL"
    group: str          # e.g., "PII"
    type: str           # e.g., "EMAIL"
    value: str          # The matched value
    start: int          # Start position in content
    end: int            # End position in content
    confidence: float = 1.0


@dataclass
class SafetyResult:
    """Result of a safety check."""
    action: Action
    detections: List[Detection] = field(default_factory=list)
    modified_content: Optional[str] = None
    message: Optional[str] = None


class Rule(ABC):
    """Abstract base class for detection rules."""

    def __init__(
        self,
        group: str,
        rule_type: str,
        mode: DetectionMode,
        enabled: bool = True,
        case_sensitive: bool = False
    ):
        self.group = group
        self.type = rule_type
        self.name = f"{group}.{rule_type}"
        self.mode = mode
        self.enabled = enabled
        self.case_sensitive = case_sensitive

    @abstractmethod
    def detect(self, content: str) -> List[Detection]:
        """Detect sensitive content. Returns list of detections."""
        pass


class RegexRule(Rule):
    """Rule that uses regex pattern matching."""

    def __init__(
        self,
        group: str,
        rule_type: str,
        pattern: str,
        enabled: bool = True,
        case_sensitive: bool = False
    ):
        super().__init__(group, rule_type, DetectionMode.REGEX, enabled, case_sensitive)
        flags = 0 if case_sensitive else re.IGNORECASE
        self.pattern: Pattern = re.compile(pattern, flags)

    def detect(self, content: str) -> List[Detection]:
        if not self.enabled:
            return []

        detections = []
        for match in self.pattern.finditer(content):
            detections.append(Detection(
                rule_name=self.name,
                group=self.group,
                type=self.type,
                value=match.group(),
                start=match.start(),
                end=match.end()
            ))
        return detections


class ListRule(Rule):
    """Rule that checks for presence in a predefined list."""

    def __init__(
        self,
        group: str,
        rule_type: str,
        values: List[str],
        enabled: bool = True,
        case_sensitive: bool = False,
        word_boundary: bool = True
    ):
        super().__init__(group, rule_type, DetectionMode.LIST, enabled, case_sensitive)
        self.word_boundary = word_boundary

        # Build optimized lookup
        if case_sensitive:
            self.values_set: Set[str] = set(values)
            self.values_list = values
        else:
            self.values_set = set(v.lower() for v in values)
            self.values_list = [v.lower() for v in values]

        # Build regex for efficient matching
        escaped_values = [re.escape(v) for v in values]
        pattern_str = '|'.join(escaped_values)
        if word_boundary:
            pattern_str = r'\b(' + pattern_str + r')\b'
        else:
            pattern_str = '(' + pattern_str + ')'

        flags = 0 if case_sensitive else re.IGNORECASE
        self.pattern: Pattern = re.compile(pattern_str, flags)

    def detect(self, content: str) -> List[Detection]:
        if not self.enabled:
            return []

        detections = []
        for match in self.pattern.finditer(content):
            matched_value = match.group(1)
            # Verify it's in our set
            check_value = matched_value if self.case_sensitive else matched_value.lower()
            if check_value in self.values_set:
                detections.append(Detection(
                    rule_name=self.name,
                    group=self.group,
                    type=self.type,
                    value=matched_value,
                    start=match.start(),
                    end=match.end()
                ))
        return detections


class HybridRule(Rule):
    """
    Rule that combines regex and/or list matching with optional validator.
    Candidates are found via regex OR list, then validated.
    """

    def __init__(
        self,
        group: str,
        rule_type: str,
        pattern: Optional[str] = None,
        values: Optional[List[str]] = None,
        validator: Optional[str] = None,
        enabled: bool = True,
        case_sensitive: bool = False
    ):
        super().__init__(group, rule_type, DetectionMode.HYBRID, enabled, case_sensitive)

        flags = 0 if case_sensitive else re.IGNORECASE

        # Regex component
        self.regex_pattern: Optional[Pattern] = None
        if pattern:
            self.regex_pattern = re.compile(pattern, flags)

        # List component
        self.values_set: Optional[Set[str]] = None
        self.list_pattern: Optional[Pattern] = None
        if values:
            if case_sensitive:
                self.values_set = set(values)
            else:
                self.values_set = set(v.lower() for v in values)

            escaped_values = [re.escape(v) for v in values]
            pattern_str = r'\b(' + '|'.join(escaped_values) + r')\b'
            self.list_pattern = re.compile(pattern_str, flags)

        # Validator function
        self.validator_fn: Optional[Callable[[str], bool]] = None
        if validator:
            self.validator_fn = self._load_validator(validator)

    def _load_validator(self, validator_path: str) -> Optional[Callable[[str], bool]]:
        """Dynamically load a validator function from module path."""
        try:
            parts = validator_path.rsplit('.', 1)
            if len(parts) == 2:
                module_path, func_name = parts
                module = importlib.import_module(module_path)
                return getattr(module, func_name)
            else:
                logger.warning(f"Invalid validator path: {validator_path}")
                return None
        except (ImportError, AttributeError) as e:
            logger.warning(f"Failed to load validator {validator_path}: {e}")
            return None

    def detect(self, content: str) -> List[Detection]:
        if not self.enabled:
            return []

        candidates: Dict[Tuple[int, int], str] = {}

        # Collect candidates from regex
        if self.regex_pattern:
            for match in self.regex_pattern.finditer(content):
                key = (match.start(), match.end())
                candidates[key] = match.group()

        # Collect candidates from list
        if self.list_pattern and self.values_set:
            for match in self.list_pattern.finditer(content):
                key = (match.start(), match.end())
                matched_value = match.group(1)
                check_value = matched_value if self.case_sensitive else matched_value.lower()
                if check_value in self.values_set:
                    candidates[key] = matched_value

        # Validate candidates
        detections = []
        for (start, end), value in candidates.items():
            # If validator exists, check it
            if self.validator_fn:
                # Clean the value for validation (remove spaces, dashes)
                clean_value = re.sub(r'[\s\-]', '', value)
                if not self.validator_fn(clean_value):
                    continue

            detections.append(Detection(
                rule_name=self.name,
                group=self.group,
                type=self.type,
                value=value,
                start=start,
                end=end
            ))

        return detections


class SafetyEngine:
    """
    Main safety engine that loads rules from YAML and performs detection/redaction.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_dict: Optional[Dict[str, Any]] = None
    ):
        self.rules: List[Rule] = []
        self.policies: Set[str] = set()

        # Redaction settings
        self.redaction_template: str = "[REDACTED{type}]"
        self.suffix_type: bool = True

        # Action settings (separate for input and output)
        self.input_action: Action = Action.REDACT
        self.output_action: Action = Action.ALLOW
        self.block_on_jailbreak: bool = True

        # Load configuration
        if config_path:
            self._load_config_file(config_path)
        elif config_dict:
            self._load_config_dict(config_dict)
        else:
            from importlib.resources import files
            config_path_resource = files("fortifyroot").joinpath("config.yaml")
            _dict = yaml.safe_load(config_path_resource.read_text())
            self._load_config_dict(_dict)

    def _load_config_file(self, config_path: str) -> None:
        """Load configuration from YAML file."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(path, 'r') as f:
            config = yaml.safe_load(f)

        self._load_config_dict(config)

    def _load_config_dict(self, config: Dict[str, Any]) -> None:
        """Load configuration from dictionary."""
        # Load settings
        settings = config.get('settings', {})
        self.redaction_template = settings.get('redaction_template', "[REDACTED{type}]")
        self.suffix_type = settings.get('suffix_type', True)
        self.input_action = Action(settings.get('input_action', 'redact'))
        self.output_action = Action(settings.get('output_action', 'allow'))
        self.block_on_jailbreak = settings.get('block_on_jailbreak', True)

        # Load rules
        for rule_def in config.get('rules', []):
            rule = self._create_rule(rule_def)
            if rule:
                self.rules.append(rule)
                self.policies.add(rule.group)

    def _create_rule(self, rule_def: Dict[str, Any]) -> Optional[Rule]:
        """Create a rule instance from definition."""
        try:
            group = rule_def['group']
            rule_type = rule_def['type']
            mode = DetectionMode(rule_def.get('mode', 'regex'))
            enabled = rule_def.get('enabled', True)
            case_sensitive = rule_def.get('case_sensitive', False)

            if mode == DetectionMode.REGEX:
                return RegexRule(
                    group=group,
                    rule_type=rule_type,
                    pattern=rule_def['pattern'],
                    enabled=enabled,
                    case_sensitive=case_sensitive
                )
            elif mode == DetectionMode.LIST:
                return ListRule(
                    group=group,
                    rule_type=rule_type,
                    values=rule_def['values'],
                    enabled=enabled,
                    case_sensitive=case_sensitive,
                    word_boundary=rule_def.get('word_boundary', True)
                )
            elif mode == DetectionMode.HYBRID:
                return HybridRule(
                    group=group,
                    rule_type=rule_type,
                    pattern=rule_def.get('pattern'),
                    values=rule_def.get('values'),
                    validator=rule_def.get('validator'),
                    enabled=enabled,
                    case_sensitive=case_sensitive
                )
        except (KeyError, ValueError) as e:
            logger.warning(f"Failed to create rule: {e}")
            return None

        return None

    def detect(
        self,
        content: str,
        policies: Optional[List[str]] = None
    ) -> List[Detection]:
        """
        Detect sensitive content based on active policies.

        Args:
            content: Text content to scan
            policies: List of policy groups to check (e.g., ["PII", "PCI"])
                     If None, all policies are checked.

        Returns:
            List of Detection objects
        """
        if not content:
            return []

        active_policies = set(policies) if policies else self.policies

        all_detections: List[Detection] = []
        for rule in self.rules:
            if rule.group in active_policies:
                detections = rule.detect(content)
                all_detections.extend(detections)

        # Sort by position (for proper redaction order)
        all_detections.sort(key=lambda d: (d.start, -d.end))

        # Remove overlapping detections (keep the first/longest)
        filtered: List[Detection] = []
        last_end = -1
        for det in all_detections:
            if det.start >= last_end:
                filtered.append(det)
                last_end = det.end

        return filtered

    def redact(
        self,
        content: str,
        detections: List[Detection]
    ) -> str:
        """
        Redact detected content with placeholders.

        Args:
            content: Original content
            detections: List of detections to redact

        Returns:
            Redacted content string
        """
        if not detections:
            return content

        # Sort by position descending to replace from end to start
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)

        result = content
        for det in sorted_detections:
            placeholder = self._render_placeholder(det)
            result = result[:det.start] + placeholder + result[det.end:]

        return result

    def _render_placeholder(self, detection: Detection) -> str:
        """Render redaction placeholder for a detection."""
        if self.suffix_type:
            type_suffix = f"-{detection.rule_name}"
        else:
            type_suffix = ""

        return self.redaction_template.replace("{type}", type_suffix)

    def check(
        self,
        content: str,
        policies: Optional[List[str]] = None,
        action_override: Optional[Action] = None,
        direction: str = "input"
    ) -> SafetyResult:
        """
        Perform full safety check on content.

        Args:
            content: Text content to check
            policies: Policy groups to check
            action_override: Override default action
            direction: "input" or "output" - determines default action

        Returns:
            SafetyResult with action and optional modified content
        """
        detections = self.detect(content, policies)

        if not detections:
            return SafetyResult(action=Action.ALLOW, detections=[])

        # Determine action based on direction or override
        if action_override:
            action = action_override
        elif direction == "output":
            action = self.output_action
        else:
            action = self.input_action

        # Check for jailbreak - always block
        has_jailbreak = any(d.group == "JAILBREAK" for d in detections)
        if has_jailbreak and self.block_on_jailbreak:
            return SafetyResult(
                action=Action.BLOCK,
                detections=detections,
                message="Jailbreak attempt detected"
            )

        # Apply action
        if action == Action.BLOCK:
            return SafetyResult(
                action=Action.BLOCK,
                detections=detections,
                message=f"Blocked: {len(detections)} sensitive items detected"
            )
        elif action == Action.REDACT:
            redacted = self.redact(content, detections)
            return SafetyResult(
                action=Action.REDACT,
                detections=detections,
                modified_content=redacted
            )
        else:
            return SafetyResult(
                action=Action.ALLOW,
                detections=detections
            )

    def add_rule(self, rule: Rule) -> None:
        """Add a rule dynamically."""
        self.rules.append(rule)
        self.policies.add(rule.group)

    def get_rules_by_group(self, group: str) -> List[Rule]:
        """Get all rules for a specific group."""
        return [r for r in self.rules if r.group == group]

    def enable_policy(self, group: str) -> None:
        """Enable all rules in a policy group."""
        for rule in self.rules:
            if rule.group == group:
                rule.enabled = True

    def disable_policy(self, group: str) -> None:
        """Disable all rules in a policy group."""
        for rule in self.rules:
            if rule.group == group:
                rule.enabled = False


# Built-in validators module path: fortifyroot.validators
# These can be referenced in config as "fortifyroot.validators.luhn"

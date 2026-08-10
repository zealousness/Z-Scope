"""Versioned, non-executable YAML rules and Python rule-provider extensions."""

from __future__ import annotations

import importlib.metadata
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence

import yaml

RULE_PACK_VERSION = 1
RULE_PROVIDER_ENTRY_POINT = "zscope.rule_providers"
SUPPORTED_LANGUAGES = {"c_cpp", "java"}
RULE_FIELDS = {
    "id",
    "language",
    "cwe",
    "defect_class",
    "severity",
    "match",
    "guards",
    "evidence",
    "skill",
}
PACK_FIELDS = {"rule_pack_version", "name", "rules", "tests"}


class RulePackError(ValueError):
    """Raised when a rule pack is ambiguous, unsafe, or structurally invalid."""


@dataclass(frozen=True)
class RuleContext:
    language: str
    project_root: Path
    function: str
    file_path: str
    code: str
    annotations: Sequence[Any] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Candidate:
    rule_id: str
    language: str
    cwe: str
    defect_class: str
    severity: str
    skill: str
    function: str
    file_path: str
    line: int
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_issue(self) -> Dict[str, Any]:
        location = f"{self.file_path}:{self.line}" if self.file_path else str(self.line)
        return {
            "rule": self.rule_id,
            "rule_id": self.rule_id,
            "category": self.defect_class,
            "defect_class": self.defect_class,
            "cwe": self.cwe,
            "severity": self.severity,
            "skill": self.skill,
            "function": self.function,
            "file": self.file_path,
            "line": self.line,
            "location": location,
            "candidate_source": "external_rule_pack",
            "validation_required": True,
            "evidence_pack": {
                "candidate_source": "external_rule_pack",
                "rule_id": self.rule_id,
                "language": self.language,
                "evidence": dict(self.evidence),
            },
        }


class ExecutableRule(Protocol):
    id: str
    language: str

    def evaluate(self, context: RuleContext) -> Iterable[Candidate]:
        """Return candidates for one normalized function context."""


class RuleProvider(Protocol):
    def rules(self) -> Iterable[ExecutableRule]:
        """Return the provider's executable rules."""


def builtin_rule_ids() -> frozenset[str]:
    """Return stable IDs already owned by built-in registries."""

    from ..core.candidates.java_rules import JavaRuleCandidateGenerator

    return frozenset(rule.rule_id for rule in JavaRuleCandidateGenerator._RULES)


@dataclass(frozen=True)
class YamlRule:
    id: str
    language: str
    cwe: str
    defect_class: str
    severity: str
    pattern: str
    flags: int
    guards: Sequence[str]
    evidence: Mapping[str, Any]
    skill: str

    def evaluate(self, context: RuleContext) -> Iterable[Candidate]:
        if context.language != self.language:
            return []
        if any(re.search(guard, context.code, self.flags) for guard in self.guards):
            return []
        candidates: List[Candidate] = []
        for match in re.finditer(self.pattern, context.code, self.flags):
            line = context.code.count("\n", 0, match.start()) + 1
            candidates.append(
                Candidate(
                    rule_id=self.id,
                    language=self.language,
                    cwe=self.cwe,
                    defect_class=self.defect_class,
                    severity=self.severity,
                    skill=self.skill,
                    function=context.function,
                    file_path=context.file_path,
                    line=line,
                    evidence={
                        **dict(self.evidence),
                        "matched_text": match.group(0),
                        "match_span": [match.start(), match.end()],
                    },
                )
            )
        return candidates


@dataclass
class RulePack:
    path: Path
    name: str
    rules: List[YamlRule]
    tests: List[Dict[str, Any]]


class RuleRegistry:
    """Load explicitly configured YAML packs and selected Python providers."""

    def __init__(
        self,
        *,
        disabled_ids: Sequence[str] = (),
        reserved_ids: Optional[Sequence[str]] = None,
    ) -> None:
        self.disabled_ids = {str(item) for item in disabled_ids}
        self.reserved_ids = set(builtin_rule_ids() if reserved_ids is None else reserved_ids)
        self._rules: Dict[str, ExecutableRule] = {}
        self.packs: List[RulePack] = []

    @property
    def rules(self) -> List[ExecutableRule]:
        return [rule for rule_id, rule in self._rules.items() if rule_id not in self.disabled_ids]

    @property
    def all_rules(self) -> Mapping[str, ExecutableRule]:
        return dict(self._rules)

    def add(self, rule: ExecutableRule, *, source: str) -> None:
        rule_id = str(getattr(rule, "id", "") or "")
        language = str(getattr(rule, "language", "") or "")
        if not rule_id:
            raise RulePackError(f"{source}: rule id is required")
        if language not in SUPPORTED_LANGUAGES:
            raise RulePackError(f"{source}: rule {rule_id!r} has unsupported language {language!r}")
        if rule_id in self.reserved_ids:
            raise RulePackError(
                f"duplicate rule id {rule_id!r}; user packs cannot override built-in rules"
            )
        if rule_id in self._rules:
            raise RulePackError(f"duplicate rule id {rule_id!r}; user packs cannot override rules")
        self._rules[rule_id] = rule

    def load_pack(self, path: Path, *, known_skills: Optional[Sequence[str]] = None) -> RulePack:
        resolved = path.expanduser().resolve()
        if not resolved.is_file():
            raise RulePackError(f"rule pack does not exist: {resolved}")
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise RulePackError(f"{resolved}: rule pack must be a mapping")
        unknown = sorted(set(raw) - PACK_FIELDS)
        if unknown:
            raise RulePackError(f"{resolved}: unknown pack fields: {', '.join(unknown)}")
        if raw.get("rule_pack_version") != RULE_PACK_VERSION:
            raise RulePackError(f"{resolved}: rule_pack_version must be {RULE_PACK_VERSION}")
        raw_rules = raw.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise RulePackError(f"{resolved}: rules must be a non-empty list")
        skills = set(known_skills or ())
        rules = [self._parse_yaml_rule(item, resolved, skills) for item in raw_rules]
        tests = raw.get("tests") or []
        if not isinstance(tests, list) or any(not isinstance(item, dict) for item in tests):
            raise RulePackError(f"{resolved}: tests must be a list of mappings")
        pack = RulePack(
            path=resolved,
            name=str(raw.get("name") or resolved.stem),
            rules=rules,
            tests=[dict(item) for item in tests],
        )
        for rule in pack.rules:
            self.add(rule, source=str(resolved))
        self.packs.append(pack)
        return pack

    def load_providers(self, names: Sequence[str]) -> None:
        selected = {str(name) for name in names if str(name)}
        if not selected:
            return
        available = self._provider_entry_points()
        missing = sorted(selected - set(available))
        if missing:
            raise RulePackError(f"unknown rule providers: {', '.join(missing)}")
        for name in sorted(selected):
            loaded = available[name].load()
            provider = loaded() if isinstance(loaded, type) else loaded
            if not hasattr(provider, "rules"):
                raise RulePackError(f"provider {name!r} does not implement rules()")
            for rule in provider.rules():
                self.add(rule, source=f"entry point {name}")

    def evaluate(self, context: RuleContext) -> List[Candidate]:
        candidates: List[Candidate] = []
        for rule in self.rules:
            if str(getattr(rule, "language", "")) != context.language:
                continue
            result = rule.evaluate(context)
            for candidate in result:
                if not isinstance(candidate, Candidate):
                    raise RulePackError(
                        f"rule {getattr(rule, 'id', '<unknown>')!r} returned a non-Candidate value"
                    )
                candidates.append(candidate)
        return candidates

    @staticmethod
    def _provider_entry_points() -> Dict[str, Any]:
        entries = importlib.metadata.entry_points()
        if hasattr(entries, "select"):
            selected = entries.select(group=RULE_PROVIDER_ENTRY_POINT)
        else:  # Python 3.9 importlib.metadata API
            selected = entries.get(RULE_PROVIDER_ENTRY_POINT, [])
        return {entry.name: entry for entry in selected}

    @staticmethod
    def _parse_yaml_rule(
        raw: Any,
        path: Path,
        known_skills: Sequence[str],
    ) -> YamlRule:
        if not isinstance(raw, dict):
            raise RulePackError(f"{path}: each rule must be a mapping")
        unknown = sorted(set(raw) - RULE_FIELDS)
        if unknown:
            raise RulePackError(f"{path}: unknown rule fields: {', '.join(unknown)}")
        missing = sorted(RULE_FIELDS - set(raw))
        if missing:
            raise RulePackError(f"{path}: missing rule fields: {', '.join(missing)}")
        rule_id = str(raw["id"] or "")
        language = str(raw["language"] or "")
        skill = str(raw["skill"] or "")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]*", rule_id):
            raise RulePackError(f"{path}: invalid stable rule id {rule_id!r}")
        if language not in SUPPORTED_LANGUAGES:
            raise RulePackError(f"{path}: unsupported language {language!r}")
        if known_skills and skill not in known_skills:
            raise RulePackError(f"{path}: rule {rule_id!r} references unknown Skill {skill!r}")
        match = raw["match"]
        if isinstance(match, str):
            pattern = match
            flags_text: Sequence[str] = ()
        elif isinstance(match, dict) and set(match) <= {"pattern", "flags"}:
            pattern = str(match.get("pattern") or "")
            flags_text = match.get("flags") or ()
        else:
            raise RulePackError(f"{path}: rule {rule_id!r} match must be a pattern mapping")
        if not pattern:
            raise RulePackError(f"{path}: rule {rule_id!r} match.pattern is required")
        if isinstance(flags_text, str) or not isinstance(flags_text, (list, tuple)):
            raise RulePackError(f"{path}: rule {rule_id!r} match.flags must be a string list")
        flags = 0
        for flag in flags_text:
            flag_name = str(flag).upper()
            if flag_name not in {"IGNORECASE", "MULTILINE", "DOTALL"}:
                raise RulePackError(f"{path}: unsupported regex flag {flag!r}")
            flags |= int(getattr(re, flag_name))
        try:
            re.compile(pattern, flags)
        except re.error as exc:
            raise RulePackError(f"{path}: invalid pattern for {rule_id!r}: {exc}") from exc
        guards = raw["guards"]
        if not isinstance(guards, list) or any(not isinstance(item, str) for item in guards):
            raise RulePackError(f"{path}: rule {rule_id!r} guards must be a string list")
        for guard in guards:
            try:
                re.compile(guard, flags)
            except re.error as exc:
                raise RulePackError(f"{path}: invalid guard for {rule_id!r}: {exc}") from exc
        evidence = raw["evidence"]
        if not isinstance(evidence, dict):
            raise RulePackError(f"{path}: rule {rule_id!r} evidence must be a mapping")
        severity = str(raw["severity"] or "").lower()
        if severity not in {"low", "medium", "high", "critical"}:
            raise RulePackError(f"{path}: rule {rule_id!r} has invalid severity {severity!r}")
        if not str(raw["cwe"] or "") or not str(raw["defect_class"] or ""):
            raise RulePackError(f"{path}: rule {rule_id!r} requires cwe and defect_class")
        return YamlRule(
            id=rule_id,
            language=language,
            cwe=str(raw["cwe"] or ""),
            defect_class=str(raw["defect_class"] or ""),
            severity=severity,
            pattern=pattern,
            flags=flags,
            guards=list(guards),
            evidence=dict(evidence),
            skill=skill,
        )


def run_pack_tests(pack: RulePack, registry: RuleRegistry) -> List[str]:
    """Run embedded positive/negative examples and optional candidate snapshots."""

    failures: List[str] = []
    coverage: Dict[str, set] = {rule.id: set() for rule in pack.rules}
    for index, case in enumerate(pack.tests, start=1):
        rule_id = str(case.get("rule_id") or "")
        expect = case.get("expect")
        if rule_id not in coverage or not isinstance(expect, bool):
            failures.append(f"test {index}: rule_id and boolean expect are required")
            continue
        rule = next(rule for rule in pack.rules if rule.id == rule_id)
        context = RuleContext(
            language=str(case.get("language") or rule.language),
            project_root=pack.path.parent,
            function=str(case.get("function") or "fixture"),
            file_path=str(case.get("file") or "fixture.txt"),
            code=str(case.get("code") or ""),
        )
        candidates = [item for item in registry.evaluate(context) if item.rule_id == rule_id]
        actual = bool(candidates)
        coverage[rule_id].add(expect)
        if actual != expect:
            failures.append(f"test {index} ({rule_id}): expected {expect}, got {actual}")
            continue
        expected = case.get("candidate")
        if expect and expected is not None:
            if not isinstance(expected, dict):
                failures.append(f"test {index} ({rule_id}): candidate snapshot must be a mapping")
            else:
                issue = candidates[0].to_issue()
                for key, value in expected.items():
                    if issue.get(key) != value:
                        failures.append(
                            f"test {index} ({rule_id}): candidate.{key} expected {value!r}, "
                            f"got {issue.get(key)!r}"
                        )
    for rule_id, outcomes in coverage.items():
        if outcomes != {False, True}:
            failures.append(f"{rule_id}: requires at least one positive and one negative test")
    return failures

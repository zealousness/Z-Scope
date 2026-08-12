"""Strict YAML rule packs, Python Provider V2, and shared rule preflight."""

from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import re
import threading
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

import yaml

from .catalog import (
    EffectiveRuleSet,
    RuleCatalog,
    RuleCatalogError,
    RuleDescriptor,
    _UniqueKeyLoader,
    external_descriptor,
    packaged_skill_languages,
)
from .implementation import validate_builtin_implementation

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


class RulePackError(RuleCatalogError):
    """Raised when a rule pack or provider violates the extension contract."""


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
    """Provider V2 output; all governance metadata is bound by RuleRegistry."""

    rule_id: str
    function: str
    file_path: str
    line: int
    evidence: Mapping[str, Any] = field(default_factory=dict)
    _descriptor: Optional[RuleDescriptor] = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def _bind(self, descriptor: RuleDescriptor) -> "Candidate":
        if self.rule_id != descriptor.id:
            raise RulePackError(f"rule {descriptor.id!r} returned candidate for {self.rule_id!r}")
        if not isinstance(self.function, str) or not isinstance(self.file_path, str):
            raise RulePackError(
                f"rule {descriptor.id!r} candidate function and file_path must be strings"
            )
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 0:
            raise RulePackError(
                f"rule {descriptor.id!r} candidate line must be a non-negative integer"
            )
        if not isinstance(self.evidence, Mapping):
            raise RulePackError(f"rule {descriptor.id!r} candidate evidence must be a mapping")
        bound = Candidate(
            rule_id=self.rule_id,
            function=self.function,
            file_path=self.file_path,
            line=self.line,
            evidence=dict(self.evidence),
        )
        object.__setattr__(bound, "_descriptor", descriptor)
        return bound

    @property
    def descriptor(self) -> RuleDescriptor:
        if self._descriptor is None:
            raise RulePackError(
                "candidate is not bound to a registered descriptor; evaluate it through RuleRegistry"
            )
        return self._descriptor

    def to_issue(self) -> Dict[str, Any]:
        descriptor = self.descriptor
        location = f"{self.file_path}:{self.line}" if self.file_path else str(self.line)
        candidate_source = (
            "external_rule_pack" if descriptor.engine == "yaml_pack" else "external_rule_provider"
        )
        governance = {
            "rule_id": descriptor.id,
            "rule_engine": descriptor.engine,
            "rule_revision": descriptor.revision,
            "rule_source": descriptor.source,
            "rule_status": descriptor.status,
            "skill": descriptor.skill,
        }
        return {
            "rule": descriptor.id,
            "rule_id": descriptor.id,
            "category": descriptor.defect_class,
            "defect_class": descriptor.defect_class,
            "cwe": descriptor.cwe,
            "severity": descriptor.default_severity,
            "skill": descriptor.skill,
            "function": self.function,
            "file": self.file_path,
            "line": self.line,
            "location": location,
            "candidate_source": candidate_source,
            "candidate_kind": "deterministic_rule",
            "validation_required": True,
            **governance,
            "evidence_pack": {
                "candidate_source": candidate_source,
                "candidate_kind": "deterministic_rule",
                "language": descriptor.language,
                **governance,
                "rule_descriptor": dict(governance),
                "evidence": dict(self.evidence),
            },
        }


class ExecutableRule(Protocol):
    @property
    def descriptor(self) -> RuleDescriptor:
        """Return the immutable governance descriptor for this executable rule."""

    def evaluate(self, context: RuleContext) -> Iterable[Candidate]:
        """Return minimal V2 candidates for one normalized function context."""


class RuleProvider(Protocol):
    def rules(self) -> Iterable[ExecutableRule]:
        """Return strict Provider V2 executable rules."""


def builtin_rule_ids() -> frozenset[str]:
    """Return IDs owned by the complete built-in rule catalog."""

    return RuleCatalog.builtin().ids


@dataclass(frozen=True)
class YamlRule:
    descriptor: RuleDescriptor
    pattern: str
    flags: int
    guards: Tuple[str, ...]
    evidence: Mapping[str, Any]

    @property
    def id(self) -> str:
        return self.descriptor.id

    @property
    def language(self) -> str:
        return self.descriptor.language

    def evaluate(self, context: RuleContext) -> Iterable[Candidate]:
        if context.language != self.descriptor.language:
            return []
        if any(re.search(guard, context.code, self.flags) for guard in self.guards):
            return []
        candidates: List[Candidate] = []
        for match in re.finditer(self.pattern, context.code, self.flags):
            line = context.code.count("\n", 0, match.start()) + 1
            candidates.append(
                Candidate(
                    rule_id=self.descriptor.id,
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


@dataclass(frozen=True)
class RulePack:
    path: Path
    name: str
    rules: Tuple[YamlRule, ...]
    tests: Tuple[Mapping[str, Any], ...]
    sha256: str


class RuleRegistry:
    """Load explicit YAML packs and strict Python Provider V2 entry points."""

    def __init__(
        self,
        *,
        disabled_ids: Sequence[str] = (),
        reserved_ids: Optional[Sequence[str]] = None,
        catalog: Optional[RuleCatalog] = None,
        skill_languages: Optional[Mapping[str, Sequence[str]]] = None,
    ) -> None:
        self.catalog = catalog or RuleCatalog.builtin()
        self.skill_languages = dict(skill_languages or packaged_skill_languages())
        self.disabled_ids = {str(item) for item in disabled_ids}
        self.reserved_ids = set(self.catalog.ids)
        if reserved_ids is not None:
            self.reserved_ids.update(str(item) for item in reserved_ids)
        self._rules: Dict[str, ExecutableRule] = {}
        self._descriptors: Dict[str, RuleDescriptor] = {}
        self._effective_rules: Optional[EffectiveRuleSet] = None
        self._packs: List[RulePack] = []
        self._extension_sources: List[Mapping[str, Any]] = []
        self._provider_rule_locks: Dict[str, threading.RLock] = {}
        self._lock = threading.RLock()
        self._sealed = False

    @property
    def rules(self) -> Tuple[ExecutableRule, ...]:
        with self._lock:
            return tuple(
                rule
                for rule_id, rule in self._rules.items()
                if self._rule_is_executable(rule_id, self._descriptors[rule_id].language)
            )

    @property
    def all_rules(self) -> Mapping[str, ExecutableRule]:
        with self._lock:
            return MappingProxyType(dict(self._rules))

    @property
    def descriptors(self) -> Tuple[RuleDescriptor, ...]:
        with self._lock:
            return tuple(self._descriptors.values())

    @property
    def packs(self) -> Tuple[RulePack, ...]:
        with self._lock:
            return tuple(self._packs)

    @property
    def extension_sources(self) -> Tuple[Mapping[str, Any], ...]:
        # Return detached records so callers cannot mutate the provenance used
        # to build the effective identity after preflight.
        with self._lock:
            return tuple(MappingProxyType(deepcopy(dict(item))) for item in self._extension_sources)

    @property
    def effective_catalog(self) -> RuleCatalog:
        with self._lock:
            descriptors = tuple(self._descriptors.values())
        return self.catalog.with_extensions(descriptors) if descriptors else self.catalog

    def bind_effective_rules(self, effective: EffectiveRuleSet) -> None:
        """Bind the immutable preflight result used to authorize execution.

        Registration and execution are deliberately separate: providers are
        imported during preflight so their descriptors participate in the
        catalog, but only rules marked ``enabled`` for the selected language
        and backend may evaluate source code.
        """

        with self._lock:
            self._ensure_mutable("bind effective rules")
            if effective.extension_registry is not self:
                raise RulePackError(
                    "effective rule set extension_registry does not reference this registry"
                )
            missing = sorted(set(self._descriptors) - effective.catalog.ids)
            if missing:
                raise RulePackError(
                    "effective rule set does not contain registered extension rule(s): "
                    + ", ".join(missing)
                )
            if effective.catalog.source_sha256 != self.effective_catalog.source_sha256:
                raise RulePackError(
                    "effective rule catalog does not match registered extension descriptors"
                )
            self._effective_rules = effective
            self._sealed = True

    def _ensure_mutable(self, action: str) -> None:
        if self._sealed:
            raise RulePackError(f"rule registry is sealed; cannot {action} after preflight")

    def _rule_is_executable(self, rule_id: str, language: str) -> bool:
        effective = self._effective_rules
        if effective is None:
            return rule_id not in self.disabled_ids
        if language != effective.language:
            return False
        state = effective.state_for(rule_id)
        return bool(state and state.state == "enabled")

    def add(
        self,
        rule: ExecutableRule,
        *,
        source: str,
        descriptor: Optional[RuleDescriptor] = None,
    ) -> None:
        with self._lock:
            self._ensure_mutable("add rules")
            resolved = descriptor if descriptor is not None else getattr(rule, "descriptor", None)
            if not isinstance(resolved, RuleDescriptor):
                raise RulePackError(f"{source}: executable rule requires RuleDescriptor descriptor")
            rule_id = resolved.id
            if rule_id in self.reserved_ids:
                raise RulePackError(
                    f"duplicate rule id {rule_id!r}; user packs cannot override built-in rules"
                )
            if rule_id in self._rules:
                raise RulePackError(
                    f"duplicate rule id {rule_id!r}; extensions cannot override rules"
                )
            # Validate descriptor shape, extension namespace, aliases, and collisions
            # transactionally before mutating the registry.
            self.effective_catalog.with_extensions((resolved,))
            self._rules[rule_id] = rule
            self._descriptors[rule_id] = resolved
            if resolved.engine == "python_provider":
                self._provider_rule_locks[rule_id] = threading.RLock()

    def load_pack(
        self,
        path: Path,
        *,
        known_skills: Optional[Sequence[str]] = None,
        skill_languages: Optional[Mapping[str, Sequence[str]]] = None,
    ) -> RulePack:
        with self._lock:
            self._ensure_mutable("load rule packs")
        resolved = path.expanduser().resolve()
        if not resolved.is_file():
            raise RulePackError(f"rule pack does not exist: {resolved}")
        raw_bytes = resolved.read_bytes()
        try:
            raw = yaml.load(raw_bytes.decode("utf-8"), Loader=_UniqueKeyLoader)
        except UnicodeDecodeError as exc:
            raise RulePackError(f"{resolved}: rule pack must be UTF-8") from exc
        except yaml.YAMLError as exc:
            raise RulePackError(f"{resolved}: invalid YAML: {exc}") from exc
        except RuleCatalogError as exc:
            raise RulePackError(f"{resolved}: {exc}") from exc
        if not isinstance(raw, dict):
            raise RulePackError(f"{resolved}: rule pack must be a mapping")
        unknown = sorted(set(raw) - PACK_FIELDS)
        if unknown:
            raise RulePackError(f"{resolved}: unknown pack fields: {', '.join(unknown)}")
        pack_version = raw.get("rule_pack_version")
        if (
            isinstance(pack_version, bool)
            or not isinstance(pack_version, int)
            or pack_version != RULE_PACK_VERSION
        ):
            raise RulePackError(f"{resolved}: rule_pack_version must be {RULE_PACK_VERSION}")
        raw_rules = raw.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise RulePackError(f"{resolved}: rules must be a non-empty list")
        if skill_languages is None and known_skills is not None:
            skill_languages = {
                name: (("java",) if name.startswith("java_") else ("c_cpp",))
                for name in known_skills
            }
        if skill_languages is None:
            skill_languages = self.skill_languages
        raw_name = raw.get("name")
        if raw_name is not None and not isinstance(raw_name, str):
            raise RulePackError(f"{resolved}: name must be a string")
        pack_name = str(raw_name or resolved.stem)
        parsed = tuple(
            self._parse_yaml_rule(
                item,
                resolved,
                index=index,
                pack_name=pack_name,
                skill_languages=skill_languages,
            )
            for index, item in enumerate(raw_rules)
        )
        tests = raw.get("tests") or []
        if not isinstance(tests, list) or any(not isinstance(item, dict) for item in tests):
            raise RulePackError(f"{resolved}: tests must be a list of mappings")
        # Validate all collisions before mutating this registry.
        candidate_catalog = self.effective_catalog
        try:
            for rule in parsed:
                if rule.id in self.reserved_ids:
                    raise RulePackError(
                        f"duplicate rule id {rule.id!r}; user packs cannot override built-in rules"
                    )
                if rule.id in self._rules:
                    raise RulePackError(
                        f"duplicate rule id {rule.id!r}; extensions cannot override rules"
                    )
            candidate_catalog.with_extensions(tuple(rule.descriptor for rule in parsed))
            for rule in parsed:
                self.add(rule, source=str(resolved), descriptor=rule.descriptor)
        except RuleCatalogError as exc:
            if isinstance(exc, RulePackError):
                raise
            raise RulePackError(str(exc)) from exc
        digest = hashlib.sha256(raw_bytes).hexdigest()
        pack = RulePack(
            path=resolved,
            name=pack_name,
            rules=parsed,
            tests=tuple(dict(item) for item in tests),
            sha256=digest,
        )
        with self._lock:
            self._packs.append(pack)
            self._extension_sources.append(
                {
                    "kind": "yaml_pack",
                    "name": pack_name,
                    "path": str(resolved),
                    "sha256": digest,
                }
            )
        return pack

    def load_providers(self, names: Sequence[str]) -> None:
        with self._lock:
            self._ensure_mutable("load rule providers")
        selected_names = [str(name) for name in names if str(name)]
        if len(set(selected_names)) != len(selected_names):
            raise RulePackError("rules.providers contains duplicate provider names")
        if not selected_names:
            return
        available = self._provider_entry_points()
        missing = sorted(set(selected_names) - set(available))
        if missing:
            raise RulePackError(f"unknown rule providers: {', '.join(missing)}")
        for name in sorted(selected_names):
            entry = available[name]
            loaded = entry.load()
            provider = loaded() if isinstance(loaded, type) else loaded
            if not hasattr(provider, "rules"):
                raise RulePackError(f"provider {name!r} does not implement rules()")
            provided = list(provider.rules())
            source, source_record = self._provider_source(
                name,
                entry,
                loaded,
                provider=provider,
                rules=provided,
            )
            normalized: List[Tuple[ExecutableRule, RuleDescriptor]] = []
            for index, rule in enumerate(provided):
                descriptor = getattr(rule, "descriptor", None)
                if not isinstance(descriptor, RuleDescriptor):
                    raise RulePackError(
                        f"provider {name!r} rule[{index}] requires RuleDescriptor descriptor"
                    )
                forced = replace(
                    descriptor,
                    engine="python_provider",
                    source=source,
                    legacy_id=False,
                )
                # Recreate through the public constructor to enforce the extension namespace.
                try:
                    forced = external_descriptor(
                        rule_id=forced.id,
                        language=forced.language,
                        engine="python_provider",
                        defect_class=forced.defect_class,
                        cwe=forced.cwe,
                        skill=forced.skill,
                        severity=forced.default_severity,
                        title=forced.title,
                        summary=forced.summary,
                        source=source,
                        revision=forced.revision,
                        status=forced.status,
                        required_capabilities=forced.required_capabilities,
                        aliases=forced.aliases,
                    )
                except RuleCatalogError as exc:
                    raise RulePackError(f"provider {name!r}: {exc}") from exc
                supported_languages = self.skill_languages.get(forced.skill)
                if supported_languages is None:
                    raise RulePackError(
                        f"provider {name!r} rule {forced.id!r} references unknown Skill "
                        f"{forced.skill!r}"
                    )
                if forced.language not in supported_languages:
                    raise RulePackError(
                        f"provider {name!r} rule {forced.id!r} references Skill "
                        f"{forced.skill!r}, which does not support {forced.language}"
                    )
                normalized.append((rule, forced))
            try:
                self.effective_catalog.with_extensions(tuple(item[1] for item in normalized))
                for rule, descriptor in normalized:
                    self.add(rule, source=source, descriptor=descriptor)
            except RuleCatalogError as exc:
                if isinstance(exc, RulePackError):
                    raise
                raise RulePackError(f"provider {name!r}: {exc}") from exc
            with self._lock:
                self._extension_sources.append(source_record)

    def evaluate(self, context: RuleContext) -> List[Candidate]:
        if context.language not in SUPPORTED_LANGUAGES:
            raise RulePackError(f"unsupported rule context language {context.language!r}")
        if self._effective_rules is not None and context.language != self._effective_rules.language:
            raise RulePackError(
                "rule context language "
                f"{context.language!r} does not match effective rule language "
                f"{self._effective_rules.language!r}"
            )
        with self._lock:
            registered = tuple(
                (rule_id, rule, self._descriptors[rule_id]) for rule_id, rule in self._rules.items()
            )
        candidates: List[Candidate] = []
        for rule_id, rule, descriptor in registered:
            if descriptor.language != context.language or not self._rule_is_executable(
                rule_id, descriptor.language
            ):
                continue
            provider_lock = self._provider_rule_locks.get(rule_id)
            if provider_lock is None:
                result = list(rule.evaluate(context))
            else:
                # Provider V2 instances are shared by parallel entry workers.
                # Serialize each provider rule independently unless a future
                # protocol adds an explicit, validated thread-safety contract.
                with provider_lock:
                    result = list(rule.evaluate(context))
            for candidate in result:
                if not isinstance(candidate, Candidate):
                    raise RulePackError(f"rule {descriptor.id!r} returned a non-Candidate value")
                if candidate.rule_id != descriptor.id:
                    raise RulePackError(
                        f"rule {descriptor.id!r} returned candidate for {candidate.rule_id!r}"
                    )
                candidates.append(candidate._bind(descriptor))
        return candidates

    @staticmethod
    def _provider_entry_points() -> Dict[str, Any]:
        entries = importlib.metadata.entry_points()
        if hasattr(entries, "select"):
            selected = entries.select(group=RULE_PROVIDER_ENTRY_POINT)
        else:  # Python 3.9 importlib.metadata API
            selected = entries.get(RULE_PROVIDER_ENTRY_POINT, [])
        available: Dict[str, Any] = {}
        for entry in selected:
            name = str(entry.name)
            if name in available:
                raise RulePackError(f"duplicate installed rule provider entry point name {name!r}")
            available[name] = entry
        return available

    @staticmethod
    def _provider_source(
        name: str,
        entry: Any,
        loaded: Any,
        *,
        provider: Any,
        rules: Sequence[ExecutableRule],
    ) -> Tuple[str, Mapping[str, Any]]:
        dist = getattr(entry, "dist", None)
        dist_name = str(getattr(dist, "name", "") or "")
        dist_version = str(getattr(dist, "version", "") or "")
        module = str(getattr(loaded, "__module__", "") or "")
        components = [
            RuleRegistry._provider_implementation_component(
                "provider",
                loaded,
            ),
            RuleRegistry._provider_implementation_component(
                "provider_rules",
                getattr(provider, "rules", provider),
            ),
        ]
        for index, rule in enumerate(rules):
            descriptor = getattr(rule, "descriptor", None)
            rule_id = descriptor.id if isinstance(descriptor, RuleDescriptor) else f"rule[{index}]"
            components.append(
                RuleRegistry._provider_implementation_component(
                    f"evaluate:{rule_id}",
                    getattr(rule, "evaluate", rule),
                )
            )
        digest_builder = hashlib.sha256()
        for component in components:
            digest_builder.update(str(component["label"]).encode("utf-8", errors="surrogatepass"))
            digest_builder.update(b"\0")
            digest_builder.update(str(component["sha256"]).encode("ascii"))
            digest_builder.update(b"\0")
        digest = digest_builder.hexdigest()
        identity = (
            f"distribution:{dist_name}@{dist_version or 'unknown'}"
            if dist_name
            else f"provider:{name}"
        )
        return identity, {
            "kind": "python_provider",
            "name": name,
            "source": identity,
            "distribution": dist_name,
            "version": dist_version,
            "module": module,
            "sha256": digest,
            "implementation_sha256": digest,
            "implementation_components": components,
        }

    @staticmethod
    def _provider_implementation_component(label: str, value: Any) -> Mapping[str, str]:
        """Return a stable digest for one provider implementation component."""

        target = getattr(value, "__func__", value)
        module = str(getattr(target, "__module__", "") or "")
        qualname = str(
            getattr(target, "__qualname__", "")
            or getattr(target, "__name__", "")
            or type(target).__qualname__
        )
        path_text = ""
        payload: bytes
        digest_kind = "fallback_identity"
        try:
            source_path = inspect.getsourcefile(target)
            if source_path:
                path = Path(source_path).resolve()
                if path.is_file():
                    path_text = str(path)
                    payload = path.read_bytes()
                    digest_kind = "source_file"
                else:
                    raise OSError("source path is not a file")
            else:
                raise OSError("source path is unavailable")
        except (OSError, TypeError):
            try:
                payload = inspect.getsource(target).encode("utf-8")
                digest_kind = "source_text"
            except (OSError, TypeError):
                payload = f"{module}\0{qualname}\0{type(target).__qualname__}".encode(
                    "utf-8",
                    errors="surrogatepass",
                )
        return {
            "label": label,
            "kind": digest_kind,
            "module": module,
            "qualname": qualname,
            "path": path_text,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    @staticmethod
    def _parse_yaml_rule(
        raw: Any,
        path: Path,
        *,
        index: int,
        pack_name: str,
        skill_languages: Optional[Mapping[str, Sequence[str]]],
    ) -> YamlRule:
        field_path = f"{path}:rules[{index}]"
        if not isinstance(raw, dict):
            raise RulePackError(f"{field_path}: each rule must be a mapping")
        unknown = sorted(set(raw) - RULE_FIELDS)
        if unknown:
            raise RulePackError(f"{field_path}: unknown rule fields: {', '.join(unknown)}")
        missing = sorted(RULE_FIELDS - set(raw))
        if missing:
            raise RulePackError(f"{field_path}: missing rule fields: {', '.join(missing)}")
        rule_id = raw["id"]
        language = raw["language"]
        skill = raw["skill"]
        if (
            not isinstance(rule_id, str)
            or not isinstance(language, str)
            or not isinstance(skill, str)
        ):
            raise RulePackError(f"{field_path}: id, language, and skill must be strings")
        if language not in SUPPORTED_LANGUAGES:
            raise RulePackError(f"{field_path}: unsupported language {language!r}")
        if skill_languages is not None:
            supported = skill_languages.get(skill)
            if supported is None:
                raise RulePackError(
                    f"{field_path}: rule {rule_id!r} references unknown Skill {skill!r}"
                )
            if language not in supported:
                raise RulePackError(
                    f"{field_path}: Skill {skill!r} does not support language {language!r}"
                )
        match = raw["match"]
        if isinstance(match, str):
            pattern = match
            flags_text: Sequence[str] = ()
        elif isinstance(match, dict) and set(match) <= {"pattern", "flags"}:
            pattern_value = match.get("pattern")
            if not isinstance(pattern_value, str):
                raise RulePackError(f"{field_path}: match.pattern must be a string")
            pattern = pattern_value
            flags_text = match.get("flags") or ()
        else:
            raise RulePackError(f"{field_path}: match must be a string or pattern mapping")
        if not pattern:
            raise RulePackError(f"{field_path}: match.pattern is required")
        if isinstance(flags_text, str) or not isinstance(flags_text, (list, tuple)):
            raise RulePackError(f"{field_path}: match.flags must be a string list")
        flags = 0
        for flag in flags_text:
            if not isinstance(flag, str):
                raise RulePackError(f"{field_path}: regex flags must be strings")
            flag_name = flag.upper()
            if flag_name not in {"IGNORECASE", "MULTILINE", "DOTALL"}:
                raise RulePackError(f"{field_path}: unsupported regex flag {flag!r}")
            flags |= int(getattr(re, flag_name))
        try:
            re.compile(pattern, flags)
        except re.error as exc:
            raise RulePackError(f"{field_path}: invalid pattern for {rule_id!r}: {exc}") from exc
        guards = raw["guards"]
        if not isinstance(guards, list) or any(not isinstance(item, str) for item in guards):
            raise RulePackError(f"{field_path}: guards must be a string list")
        for guard in guards:
            try:
                re.compile(guard, flags)
            except re.error as exc:
                raise RulePackError(f"{field_path}: invalid guard for {rule_id!r}: {exc}") from exc
        evidence = raw["evidence"]
        if not isinstance(evidence, dict):
            raise RulePackError(f"{field_path}: evidence must be a mapping")
        severity = raw["severity"]
        cwe = raw["cwe"]
        defect_class = raw["defect_class"]
        if not all(isinstance(value, str) for value in (severity, cwe, defect_class)):
            raise RulePackError(f"{field_path}: severity, cwe, and defect_class must be strings")
        title = str(evidence.get("title") or rule_id)
        summary = str(evidence.get("rationale") or f"YAML rule {rule_id} from pack {pack_name}.")
        try:
            descriptor = external_descriptor(
                rule_id=rule_id,
                language=language,
                engine="yaml_pack",
                defect_class=defect_class,
                cwe=cwe,
                skill=skill,
                severity=severity.lower(),
                title=title,
                summary=summary,
                source=str(path),
            )
        except RuleCatalogError as exc:
            raise RulePackError(f"{field_path}: {exc}") from exc
        return YamlRule(
            descriptor=descriptor,
            pattern=pattern,
            flags=flags,
            guards=tuple(guards),
            evidence=dict(evidence),
        )


def preflight_rules(config: Any, *, spec_registry: Optional[Any] = None) -> EffectiveRuleSet:
    """Build and cache the one effective rule universe shared by every ingress."""

    existing = getattr(config, "effective_rules", None)
    if isinstance(existing, EffectiveRuleSet):
        return existing
    if spec_registry is None:
        from ..orchestration.specs import SpecRegistry

        project_root = Path(config.project.project_root)
        spec_registry = SpecRegistry(project_root=project_root)
    skill_languages = {
        name: tuple(getattr(skill, "languages", ()) or ())
        for name, skill in spec_registry.skills.items()
    }
    catalog = RuleCatalog.builtin(skill_languages=skill_languages)
    validate_builtin_implementation(catalog)
    rules_config = config.rules
    registry = RuleRegistry(
        disabled_ids=tuple(rules_config.disabled_ids),
        catalog=catalog,
        skill_languages=skill_languages,
    )
    project_root = Path(config.project.project_root)
    for configured in rules_config.packs:
        path = Path(str(configured)).expanduser()
        if not path.is_absolute():
            path = project_root / path
        registry.load_pack(path, skill_languages=skill_languages)
    registry.load_providers(rules_config.providers)
    sources = tuple(
        sorted(
            registry.extension_sources,
            key=lambda item: (
                str(item.get("kind") or ""),
                str(item.get("name") or ""),
                str(item.get("path") or ""),
            ),
        )
    )
    effective = EffectiveRuleSet.build(
        registry.effective_catalog,
        language=config.project.language,
        backend=config.indexing.backend,
        disabled_ids=tuple(rules_config.disabled_ids),
        extension_sources=sources,
        extension_registry=registry,
    )
    registry.bind_effective_rules(effective)
    config.effective_rules = effective
    config.rule_catalog_provenance = effective.provenance
    config.rule_validation_warnings = list(effective.warnings)
    return effective


def run_pack_tests(pack: RulePack, registry: RuleRegistry) -> List[str]:
    """Run embedded positive/negative examples and optional candidate snapshots."""

    failures: List[str] = []
    coverage: Dict[str, set[bool]] = {rule.id: set() for rule in pack.rules}
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

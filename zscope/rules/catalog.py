"""Strict, immutable governance metadata for deterministic Z-SCOPE rules."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Iterable, Iterator, Literal, Mapping, Optional, Sequence, Tuple

import yaml

RULE_CATALOG_VERSION = 2
RULE_CATALOG_SCHEMA = "zscope.rule-catalog.v2"
SUPPORTED_LANGUAGES = frozenset({"c_cpp", "java"})
BUILTIN_ENGINES = frozenset(
    {"cpp_regex", "cpp_clang_cfg", "cpp_clang_matcher", "cpp_graph", "java_local"}
)
EXTENSION_ENGINES = frozenset({"yaml_pack", "python_provider"})
SUPPORTED_ENGINES = BUILTIN_ENGINES | EXTENSION_ENGINES
SUPPORTED_STATUSES = frozenset({"stable", "experimental", "deprecated"})
SUPPORTED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
SUPPORTED_CAPABILITIES = frozenset(
    {"source_text", "clang_structure", "call_graph", "java_structure"}
)
CATALOG_FIELDS = frozenset({"rule_catalog_version", "rules"})
DESCRIPTOR_FIELDS = frozenset(
    {
        "id",
        "language",
        "engine",
        "defect_class",
        "cwe",
        "skill",
        "default_severity",
        "revision",
        "status",
        "default_enabled",
        "title",
        "summary",
        "required_capabilities",
        "aliases",
        "legacy_id",
    }
)
_ID_RE = re.compile(r"[a-z][a-z0-9_.-]*\Z")
_CWE_RE = re.compile(r"CWE-[1-9][0-9]*\Z")
_LEGACY_RULE_VARIANTS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        # This legacy detector intentionally keeps one historical rule ID while
        # classifying the concrete sink direction at runtime.
        "clang_cfg_unchecked_pointer_backtrack": MappingProxyType(
            {"buffer_underread": "CWE-127", "buffer_underwrite": "CWE-124"}
        )
    }
)


class RuleCatalogError(ValueError):
    """Raised when rule metadata is ambiguous or violates the governance contract."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> Dict[Any, Any]:
    result: Dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise RuleCatalogError(
                f"line {key_node.start_mark.line + 1}: mapping key must be hashable"
            ) from exc
        if duplicate:
            raise RuleCatalogError(
                f"line {key_node.start_mark.line + 1}: duplicate YAML key {key!r}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class RuleDescriptor:
    id: str
    language: Literal["c_cpp", "java"]
    engine: str
    defect_class: str
    cwe: str
    skill: str
    default_severity: str
    revision: int
    status: str
    title: str
    summary: str
    required_capabilities: Tuple[str, ...]
    aliases: Tuple[str, ...] = ()
    legacy_id: bool = False
    source: str = "builtin"
    default_enabled: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "language": self.language,
            "engine": self.engine,
            "defect_class": self.defect_class,
            "cwe": self.cwe,
            "skill": self.skill,
            "default_severity": self.default_severity,
            "revision": self.revision,
            "status": self.status,
            "default_enabled": self.default_enabled,
            "title": self.title,
            "summary": self.summary,
            "required_capabilities": list(self.required_capabilities),
            "aliases": list(self.aliases),
            "legacy_id": self.legacy_id,
            "source": self.source,
        }


@dataclass(frozen=True)
class RuleCatalogProvenance:
    schema_version: str
    catalog_version: int
    source_path: str
    catalog_sha256: str
    implementation_sha256: str
    effective_sha256: str
    extension_sources: Tuple[Mapping[str, Any], ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "catalog_version": self.catalog_version,
            "source_path": self.source_path,
            "catalog_sha256": self.catalog_sha256,
            "implementation_sha256": self.implementation_sha256,
            "effective_sha256": self.effective_sha256,
            "extension_sources": [dict(item) for item in self.extension_sources],
        }


@dataclass(frozen=True, init=False, repr=False, eq=False)
class RuleCatalog:
    """Immutable canonical descriptor registry with alias and collision validation."""

    version: int
    source_path: str
    source_sha256: str
    _descriptors: Tuple[RuleDescriptor, ...]
    _by_id: Mapping[str, RuleDescriptor]
    _aliases: Mapping[str, str]

    def __init__(
        self,
        descriptors: Iterable[RuleDescriptor],
        *,
        version: int = RULE_CATALOG_VERSION,
        source_path: str = "",
        source_sha256: str = "",
        validate_builtin_engines: bool = False,
    ) -> None:
        ordered = tuple(descriptors)
        if not ordered:
            raise RuleCatalogError("rule catalog must contain at least one rule")
        by_id: Dict[str, RuleDescriptor] = {}
        aliases: Dict[str, str] = {}
        for descriptor in ordered:
            self._validate_descriptor(
                descriptor,
                validate_builtin_engine=validate_builtin_engines,
            )
            if descriptor.id in by_id or descriptor.id in aliases:
                raise RuleCatalogError(f"duplicate rule id or alias {descriptor.id!r}")
            by_id[descriptor.id] = descriptor
            for alias in descriptor.aliases:
                if alias in by_id or alias in aliases:
                    raise RuleCatalogError(f"duplicate rule id or alias {alias!r}")
                aliases[alias] = descriptor.id
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "source_path", source_path)
        object.__setattr__(
            self,
            "source_sha256",
            source_sha256 or _sha256_json([item.as_dict() for item in ordered]),
        )
        object.__setattr__(self, "_descriptors", ordered)
        object.__setattr__(self, "_by_id", MappingProxyType(by_id))
        object.__setattr__(self, "_aliases", MappingProxyType(aliases))

    @property
    def descriptors(self) -> Tuple[RuleDescriptor, ...]:
        return self._descriptors

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(self._by_id)

    @property
    def aliases(self) -> Mapping[str, str]:
        return self._aliases

    def __iter__(self) -> Iterator[RuleDescriptor]:
        return iter(self._descriptors)

    def __len__(self) -> int:
        return len(self._descriptors)

    def canonical_id(self, rule_id: str) -> Optional[str]:
        value = str(rule_id or "")
        if value in self._by_id:
            return value
        return self._aliases.get(value)

    def get(self, rule_id: str) -> Optional[RuleDescriptor]:
        canonical = self.canonical_id(rule_id)
        return self._by_id.get(canonical) if canonical else None

    def require(self, rule_id: str) -> RuleDescriptor:
        descriptor = self.get(rule_id)
        if descriptor is None:
            raise RuleCatalogError(f"unknown rule id {rule_id!r}")
        return descriptor

    def with_extensions(self, descriptors: Iterable[RuleDescriptor]) -> "RuleCatalog":
        additions = tuple(descriptors)
        for descriptor in additions:
            if descriptor.engine not in EXTENSION_ENGINES:
                raise RuleCatalogError(
                    f"external rule {descriptor.id!r} must use an extension engine"
                )
            if descriptor.id.startswith("zscope."):
                raise RuleCatalogError(
                    f"external rule {descriptor.id!r} cannot use the reserved 'zscope.' namespace"
                )
            reserved_aliases = [
                alias for alias in descriptor.aliases if alias.startswith("zscope.")
            ]
            if reserved_aliases:
                raise RuleCatalogError(
                    f"external rule {descriptor.id!r} aliases cannot use the reserved "
                    f"'zscope.' namespace: {', '.join(reserved_aliases)}"
                )
        return RuleCatalog(
            (*self._descriptors, *additions),
            version=self.version,
            source_path=self.source_path,
            source_sha256=self.source_sha256,
        )

    @classmethod
    def builtin(
        cls,
        *,
        skill_languages: Optional[Mapping[str, Sequence[str]]] = None,
    ) -> "RuleCatalog":
        path = Path(__file__).with_name("builtin_catalog.yaml")
        return cls.from_path(path, skill_languages=skill_languages, builtin=True)

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        skill_languages: Optional[Mapping[str, Sequence[str]]] = None,
        builtin: bool = False,
    ) -> "RuleCatalog":
        resolved = path.expanduser().resolve()
        if not resolved.is_file():
            raise RuleCatalogError(f"rule catalog does not exist: {resolved}")
        raw_bytes = resolved.read_bytes()
        try:
            data = yaml.load(raw_bytes.decode("utf-8"), Loader=_UniqueKeyLoader)
        except UnicodeDecodeError as exc:
            raise RuleCatalogError(f"{resolved}: catalog must be UTF-8") from exc
        except yaml.YAMLError as exc:
            raise RuleCatalogError(f"{resolved}: invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise RuleCatalogError(f"{resolved}: catalog must be a mapping")
        unknown = sorted(set(data) - CATALOG_FIELDS)
        missing = sorted(CATALOG_FIELDS - set(data))
        if unknown:
            raise RuleCatalogError(f"{resolved}: unknown catalog fields: {', '.join(unknown)}")
        if missing:
            raise RuleCatalogError(f"{resolved}: missing catalog fields: {', '.join(missing)}")
        version = data["rule_catalog_version"]
        if isinstance(version, bool) or version != RULE_CATALOG_VERSION:
            raise RuleCatalogError(
                f"{resolved}: rule_catalog_version must be {RULE_CATALOG_VERSION}"
            )
        raw_rules = data["rules"]
        if not isinstance(raw_rules, list) or not raw_rules:
            raise RuleCatalogError(f"{resolved}: rules must be a non-empty list")
        languages = skill_languages
        if languages is None and builtin:
            languages = packaged_skill_languages()
        descriptors = tuple(
            _parse_descriptor(
                item,
                path=f"{resolved}:rules[{index}]",
                source="builtin" if builtin else str(resolved),
                skill_languages=languages,
                builtin=builtin,
            )
            for index, item in enumerate(raw_rules)
        )
        return cls(
            descriptors,
            version=version,
            source_path=str(resolved),
            source_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            validate_builtin_engines=builtin,
        )

    @staticmethod
    def _validate_descriptor(
        descriptor: RuleDescriptor,
        *,
        validate_builtin_engine: bool = False,
    ) -> None:
        scalar_values = {
            "id": descriptor.id,
            "language": descriptor.language,
            "engine": descriptor.engine,
            "defect_class": descriptor.defect_class,
            "cwe": descriptor.cwe,
            "skill": descriptor.skill,
            "default_severity": descriptor.default_severity,
            "status": descriptor.status,
            "title": descriptor.title,
            "summary": descriptor.summary,
            "source": descriptor.source,
        }
        for field_name, value in scalar_values.items():
            if not isinstance(value, str):
                raise RuleCatalogError(f"rule descriptor field {field_name} must be a string")
        if not isinstance(descriptor.required_capabilities, tuple) or any(
            not isinstance(item, str) for item in descriptor.required_capabilities
        ):
            raise RuleCatalogError(
                f"rule {descriptor.id!r} required_capabilities must be a string tuple"
            )
        if not isinstance(descriptor.aliases, tuple) or any(
            not isinstance(item, str) for item in descriptor.aliases
        ):
            raise RuleCatalogError(f"rule {descriptor.id!r} aliases must be a string tuple")
        if not isinstance(descriptor.legacy_id, bool):
            raise RuleCatalogError(f"rule {descriptor.id!r} legacy_id must be a boolean")
        if not isinstance(descriptor.default_enabled, bool):
            raise RuleCatalogError(f"rule {descriptor.id!r} default_enabled must be a boolean")
        if not _ID_RE.fullmatch(descriptor.id):
            raise RuleCatalogError(f"invalid stable rule id {descriptor.id!r}")
        if descriptor.language not in SUPPORTED_LANGUAGES:
            raise RuleCatalogError(
                f"rule {descriptor.id!r} has unsupported language {descriptor.language!r}"
            )
        engines = BUILTIN_ENGINES if validate_builtin_engine else SUPPORTED_ENGINES
        if descriptor.engine not in engines:
            raise RuleCatalogError(
                f"rule {descriptor.id!r} has unsupported engine {descriptor.engine!r}"
            )
        if descriptor.language == "java" and descriptor.engine.startswith("cpp_"):
            raise RuleCatalogError(f"rule {descriptor.id!r} has a C/C++ engine for Java")
        if descriptor.language == "c_cpp" and descriptor.engine == "java_local":
            raise RuleCatalogError(f"rule {descriptor.id!r} has a Java engine for C/C++")
        if not descriptor.legacy_id and descriptor.source == "builtin":
            prefix = f"zscope.{descriptor.language}.{descriptor.engine}."
            if not descriptor.id.startswith(prefix):
                raise RuleCatalogError(
                    f"new built-in rule {descriptor.id!r} must use prefix {prefix!r}"
                )
        if not _CWE_RE.fullmatch(descriptor.cwe):
            raise RuleCatalogError(f"rule {descriptor.id!r} has invalid CWE {descriptor.cwe!r}")
        if descriptor.default_severity not in SUPPORTED_SEVERITIES:
            raise RuleCatalogError(
                f"rule {descriptor.id!r} has invalid severity {descriptor.default_severity!r}"
            )
        if descriptor.status not in SUPPORTED_STATUSES:
            raise RuleCatalogError(
                f"rule {descriptor.id!r} has invalid status {descriptor.status!r}"
            )
        if descriptor.status == "experimental" and descriptor.default_enabled:
            raise RuleCatalogError(
                f"experimental rule {descriptor.id!r} must set default_enabled=false"
            )
        if isinstance(descriptor.revision, bool) or descriptor.revision < 1:
            raise RuleCatalogError(f"rule {descriptor.id!r} revision must be a positive integer")
        if not descriptor.defect_class or not descriptor.skill:
            raise RuleCatalogError(f"rule {descriptor.id!r} requires defect_class and skill")
        if not descriptor.title.strip() or not descriptor.summary.strip():
            raise RuleCatalogError(f"rule {descriptor.id!r} requires title and summary")
        unknown_caps = sorted(set(descriptor.required_capabilities) - SUPPORTED_CAPABILITIES)
        if unknown_caps:
            raise RuleCatalogError(
                f"rule {descriptor.id!r} has unknown capabilities: {', '.join(unknown_caps)}"
            )
        if len(set(descriptor.required_capabilities)) != len(descriptor.required_capabilities):
            raise RuleCatalogError(f"rule {descriptor.id!r} has duplicate capabilities")
        if len(set(descriptor.aliases)) != len(descriptor.aliases):
            raise RuleCatalogError(f"rule {descriptor.id!r} has duplicate aliases")
        for alias in descriptor.aliases:
            if not _ID_RE.fullmatch(alias):
                raise RuleCatalogError(f"rule {descriptor.id!r} has invalid alias {alias!r}")
            if alias == descriptor.id:
                raise RuleCatalogError(f"rule {descriptor.id!r} cannot alias itself")


@dataclass(frozen=True)
class EffectiveRuleState:
    descriptor: RuleDescriptor
    state: Literal["enabled", "disabled", "unavailable"]
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        value = self.descriptor.as_dict()
        value.update({"effective_status": self.state, "effective_reason": self.reason})
        return value


@dataclass(frozen=True)
class EffectiveRuleSet:
    catalog: RuleCatalog
    language: Literal["c_cpp", "java"]
    backend: str
    capabilities: frozenset[str]
    rules: Tuple[EffectiveRuleState, ...]
    provenance: RuleCatalogProvenance
    warnings: Tuple[str, ...] = ()
    qualification: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    extension_registry: Optional[Any] = field(default=None, repr=False, compare=False)

    @property
    def enabled_ids(self) -> frozenset[str]:
        return frozenset(item.descriptor.id for item in self.rules if item.state == "enabled")

    @property
    def disabled_ids(self) -> frozenset[str]:
        return frozenset(item.descriptor.id for item in self.rules if item.state == "disabled")

    @property
    def unavailable_ids(self) -> frozenset[str]:
        return frozenset(item.descriptor.id for item in self.rules if item.state == "unavailable")

    @property
    def policy(self) -> "RulePolicy":
        return RulePolicy(self)

    def descriptor(self, rule_id: str) -> RuleDescriptor:
        descriptor = self.catalog.get(rule_id)
        if descriptor is None or descriptor.language != self.language:
            raise RuleCatalogError(f"unknown {self.language} rule id {rule_id!r}")
        return descriptor

    def state_for(self, rule_id: str) -> Optional[EffectiveRuleState]:
        canonical = self.catalog.canonical_id(rule_id)
        if not canonical:
            return None
        return next((item for item in self.rules if item.descriptor.id == canonical), None)

    def is_enabled(self, rule_id: str) -> bool:
        state = self.state_for(rule_id)
        return bool(state and state.state == "enabled")

    @classmethod
    def build(
        cls,
        catalog: RuleCatalog,
        *,
        language: str,
        backend: str,
        disabled_ids: Sequence[str] = (),
        enabled_ids: Sequence[str] = (),
        extension_sources: Sequence[Mapping[str, Any]] = (),
        qualification_summary: Optional[Mapping[str, Any]] = None,
        implementation_sha256: str = "",
        extension_registry: Optional[Any] = None,
    ) -> "EffectiveRuleSet":
        if language not in SUPPORTED_LANGUAGES:
            raise RuleCatalogError(f"unsupported project language {language!r}")
        capabilities = capabilities_for(language, backend)
        seen_disabled: set[str] = set()
        canonical_disabled: set[str] = set()
        seen_enabled: set[str] = set()
        canonical_enabled: set[str] = set()
        warnings = []

        def normalize_configured_ids(
            configured_ids: Sequence[str],
            *,
            field: str,
            seen: set[str],
            canonical: set[str],
        ) -> None:
            for index, configured in enumerate(configured_ids):
                value = str(configured or "")
                if value in seen:
                    raise RuleCatalogError(f"rules.{field}[{index}]: duplicate rule id {value!r}")
                seen.add(value)
                descriptor = catalog.get(value)
                if descriptor is None:
                    suggestion = _nearest(value, catalog.ids | frozenset(catalog.aliases))
                    suffix = f"; did you mean {suggestion!r}?" if suggestion else ""
                    raise RuleCatalogError(
                        f"rules.{field}[{index}]: unknown rule id {value!r}{suffix}"
                    )
                if descriptor.language != language:
                    raise RuleCatalogError(
                        f"rules.{field}[{index}]: rule {value!r} is for "
                        f"{descriptor.language}, not {language}"
                    )
                if descriptor.id in canonical:
                    raise RuleCatalogError(
                        f"rules.{field}[{index}]: duplicate canonical rule id " f"{descriptor.id!r}"
                    )
                canonical.add(descriptor.id)

        normalize_configured_ids(
            disabled_ids,
            field="disabled_ids",
            seen=seen_disabled,
            canonical=canonical_disabled,
        )
        normalize_configured_ids(
            enabled_ids,
            field="enabled_ids",
            seen=seen_enabled,
            canonical=canonical_enabled,
        )
        states = []
        for descriptor in catalog:
            if descriptor.language != language:
                continue
            missing = sorted(set(descriptor.required_capabilities) - capabilities)
            state: Literal["enabled", "disabled", "unavailable"]
            if descriptor.id in canonical_disabled:
                state = "disabled"
                reason = "disabled_by_config"
                if missing:
                    warnings.append(
                        f"rules.disabled_ids: {descriptor.id!r} is not applicable to backend "
                        f"{backend!r} (missing {', '.join(missing)})"
                    )
            elif missing:
                state = "unavailable"
                reason = "backend_capability_missing:" + ",".join(missing)
            elif descriptor.id in canonical_enabled:
                state = "enabled"
                reason = "enabled_by_config"
            elif not descriptor.default_enabled:
                state = "disabled"
                reason = "disabled_by_default"
            else:
                state = "enabled"
                reason = "enabled_by_default"
            states.append(EffectiveRuleState(descriptor, state, reason))
        impl_hash = implementation_sha256 or implementation_hash(language=language)
        qualification = dict(qualification_summary or {})
        normalized_qualification = {
            key: value for key, value in qualification.items() if key != "source_path"
        }
        normalized = {
            "schema": RULE_CATALOG_SCHEMA,
            "catalog_sha256": catalog.source_sha256,
            "implementation_sha256": impl_hash,
            "language": language,
            "backend": backend,
            "capabilities": sorted(capabilities),
            "rules": [
                {
                    "descriptor": item.descriptor.as_dict(),
                    "state": item.state,
                    "reason": item.reason,
                }
                for item in states
            ],
            "extension_sources": [dict(item) for item in extension_sources],
            "qualification": normalized_qualification,
        }
        effective_hash = _sha256_json(normalized)
        provenance = RuleCatalogProvenance(
            schema_version=RULE_CATALOG_SCHEMA,
            catalog_version=catalog.version,
            source_path=catalog.source_path,
            catalog_sha256=catalog.source_sha256,
            implementation_sha256=impl_hash,
            effective_sha256=effective_hash,
            extension_sources=tuple(MappingProxyType(dict(item)) for item in extension_sources),
        )
        return cls(
            catalog=catalog,
            language=language,  # type: ignore[arg-type]
            backend=backend,
            capabilities=frozenset(capabilities),
            rules=tuple(states),
            provenance=provenance,
            warnings=tuple(warnings),
            qualification=MappingProxyType(qualification),
            extension_registry=extension_registry,
        )


@dataclass(frozen=True)
class RulePolicy:
    effective: EffectiveRuleSet

    def is_enabled(self, rule_id: str) -> bool:
        return self.effective.is_enabled(rule_id)

    def descriptor(self, rule_id: str) -> RuleDescriptor:
        return self.effective.descriptor(rule_id)

    def validate_issue(
        self,
        issue: Mapping[str, Any],
        *,
        language: Optional[str] = None,
    ) -> RuleDescriptor:
        rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
        if not rule_id:
            raise RuleCatalogError("deterministic candidate is missing rule_id")
        descriptor = self.descriptor(rule_id)
        if language is not None and descriptor.language != language:
            raise RuleCatalogError(
                f"rule {descriptor.id!r} is for {descriptor.language}, not {language}"
            )
        if not self.is_enabled(descriptor.id):
            raise RuleCatalogError(f"rule {descriptor.id!r} is not enabled")
        compatibility = {
            "rule": descriptor.id,
            "rule_id": descriptor.id,
            "skill": descriptor.skill,
        }
        for field_name, expected in compatibility.items():
            actual = issue.get(field_name)
            if actual not in (None, "") and str(actual) != expected:
                raise RuleCatalogError(
                    f"rule {descriptor.id!r} candidate field {field_name}={actual!r} "
                    f"does not match catalog value {expected!r}"
                )
        variants = _LEGACY_RULE_VARIANTS.get(descriptor.id)
        actual_defect = str(issue.get("defect_class") or "")
        if variants and actual_defect:
            expected_cwe = variants.get(actual_defect)
            if expected_cwe is None:
                raise RuleCatalogError(
                    f"rule {descriptor.id!r} candidate field defect_class={actual_defect!r} "
                    "is not a registered legacy variant"
                )
            actual_cwe = issue.get("cwe")
            if actual_cwe not in (None, "") and str(actual_cwe) != expected_cwe:
                raise RuleCatalogError(
                    f"rule {descriptor.id!r} candidate field cwe={actual_cwe!r} "
                    f"does not match variant value {expected_cwe!r}"
                )
        else:
            for field_name, expected in {
                "defect_class": descriptor.defect_class,
                "cwe": descriptor.cwe,
            }.items():
                actual = issue.get(field_name)
                if actual not in (None, "") and str(actual) != expected:
                    raise RuleCatalogError(
                        f"rule {descriptor.id!r} candidate field {field_name}={actual!r} "
                        f"does not match catalog value {expected!r}"
                    )
        return descriptor

    def enrich_issue(self, issue: Mapping[str, Any]) -> Dict[str, Any]:
        descriptor = self.validate_issue(issue)
        enriched = dict(issue)
        variants = _LEGACY_RULE_VARIANTS.get(descriptor.id)
        candidate_defect = str(enriched.get("defect_class") or "")
        candidate_cwe = variants.get(candidate_defect, "") if variants else ""
        enriched.update(
            {
                "rule": descriptor.id,
                "rule_id": descriptor.id,
                "defect_class": candidate_defect or descriptor.defect_class,
                "cwe": candidate_cwe or descriptor.cwe,
                "skill": descriptor.skill,
                "rule_engine": descriptor.engine,
                "rule_revision": descriptor.revision,
                "rule_source": descriptor.source,
                "rule_status": descriptor.status,
                "rule_catalog_version": self.effective.catalog.version,
                "rule_catalog_sha256": self.effective.provenance.catalog_sha256,
            }
        )
        evidence = dict(enriched.get("evidence_pack") or {})
        descriptor_ref = {
            "rule_id": descriptor.id,
            "rule_engine": descriptor.engine,
            "rule_revision": descriptor.revision,
            "rule_source": descriptor.source,
            "rule_status": descriptor.status,
            "rule_catalog_version": self.effective.catalog.version,
            "rule_catalog_sha256": self.effective.provenance.catalog_sha256,
            "skill": descriptor.skill,
        }
        evidence.update(descriptor_ref)
        evidence["rule_descriptor"] = descriptor_ref
        enriched["evidence_pack"] = evidence
        return enriched


def capabilities_for(language: str, backend: str) -> frozenset[str]:
    value = str(backend or "")
    if language == "java":
        if value not in {"java_source", "java_unified", "joern"}:
            raise RuleCatalogError(f"unsupported Java backend {value!r}")
        return frozenset({"source_text", "java_structure"})
    if language != "c_cpp":
        raise RuleCatalogError(f"unsupported project language {language!r}")
    if value == "regex":
        return frozenset({"source_text", "call_graph"})
    if value in {"clang", "unified"}:
        return frozenset({"source_text", "clang_structure", "call_graph"})
    raise RuleCatalogError(f"unsupported C/C++ backend {value!r}")


def implementation_hash(*, language: str) -> str:
    root = Path(__file__).resolve().parents[1]
    relative: Tuple[str, ...] = (
        (
            "core/candidates/regex.py",
            "core/candidates/clang_ast_cfg.py",
            "core/candidates/graph.py",
            "core/candidates/adapters.py",
            "retrieval/clang_tooling_evidence.py",
        )
        if language == "c_cpp"
        else ("core/candidates/java_rules.py",)
    )
    if language == "c_cpp":
        domain_root = root / "core" / "candidates" / "cpp_domains"
        relative += tuple(
            path.relative_to(root).as_posix()
            for path in sorted(domain_root.glob("*.py"))
            if path.is_file()
        )
    digest = hashlib.sha256()
    for value in relative:
        path = root / value
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def serialize_effective_rules(effective: EffectiveRuleSet) -> Dict[str, Any]:
    qualification = dict(effective.qualification)
    raw_qualification_rows = qualification.get("rules")
    qualification_by_rule = {
        (str(item.get("rule_id") or ""), int(item.get("revision") or 0)): dict(item)
        for item in raw_qualification_rows or []
        if isinstance(item, Mapping)
        and str(item.get("rule_id") or "")
        and isinstance(item.get("revision"), int)
        and not isinstance(item.get("revision"), bool)
    }

    def serialized(item: EffectiveRuleState) -> Dict[str, Any]:
        row = item.as_dict()
        qualification_row = qualification_by_rule.get(
            (item.descriptor.id, item.descriptor.revision)
        )
        if qualification_row is not None:
            row.update(
                {
                    "qualification_state": str(
                        qualification_row.get("state")
                        or qualification_row.get("qualification_state")
                        or "pending"
                    ),
                    "qualification_evidence_verified": bool(
                        qualification_row.get("evidence_verified")
                    ),
                    "qualification_inherited_legacy_pending": bool(
                        qualification_row.get("inherited_legacy_pending")
                    ),
                }
            )
        else:
            row.update(
                {
                    "qualification_state": "not_required",
                    "qualification_evidence_verified": False,
                    "qualification_inherited_legacy_pending": False,
                }
            )
        return row

    rows = [serialized(item) for item in effective.rules]
    enabled = [item for item in rows if item["effective_status"] == "enabled"]
    disabled = [item for item in rows if item["effective_status"] == "disabled"]
    unavailable = [item for item in rows if item["effective_status"] == "unavailable"]
    return {
        **effective.provenance.as_dict(),
        "language": effective.language,
        "backend": effective.backend,
        "capabilities": sorted(effective.capabilities),
        "summary": {
            "total": len(effective.rules),
            "enabled": len(enabled),
            "disabled": len(disabled),
            "unavailable": len(unavailable),
        },
        "enabled_ids": [item["id"] for item in enabled],
        "disabled": [{"id": item["id"], "reason": item["effective_reason"]} for item in disabled],
        "unavailable": [
            {"id": item["id"], "reason": item["effective_reason"]} for item in unavailable
        ],
        "rules": rows,
        "warnings": list(effective.warnings),
        "qualification": qualification,
    }


def _parse_descriptor(
    raw: Any,
    *,
    path: str,
    source: str,
    skill_languages: Optional[Mapping[str, Sequence[str]]],
    builtin: bool,
) -> RuleDescriptor:
    if not isinstance(raw, dict):
        raise RuleCatalogError(f"{path}: rule descriptor must be a mapping")
    unknown = sorted(set(raw) - DESCRIPTOR_FIELDS)
    # ``default_enabled`` is the only catalog-v2 migration field.  It may be
    # omitted by packaged legacy rows and is materialized as ``True`` below;
    # new rules must always state it explicitly.
    missing = sorted((DESCRIPTOR_FIELDS - {"default_enabled"}) - set(raw))
    if unknown:
        raise RuleCatalogError(f"{path}: unknown fields: {', '.join(unknown)}")
    if missing:
        raise RuleCatalogError(f"{path}: missing fields: {', '.join(missing)}")
    list_fields: Dict[str, Tuple[str, ...]] = {}
    for key in ("required_capabilities", "aliases"):
        value = raw[key]
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise RuleCatalogError(f"{path}.{key}: must be a string list")
        list_fields[key] = tuple(value)
    language = raw["language"]
    revision = raw["revision"]
    legacy_id = raw["legacy_id"]
    if not isinstance(language, str):
        raise RuleCatalogError(f"{path}.language: must be a string")
    if isinstance(revision, bool) or not isinstance(revision, int):
        raise RuleCatalogError(f"{path}.revision: must be a positive integer")
    if not isinstance(legacy_id, bool):
        raise RuleCatalogError(f"{path}.legacy_id: must be a boolean")
    scalar_fields = (
        "id",
        "engine",
        "defect_class",
        "cwe",
        "skill",
        "default_severity",
        "status",
        "title",
        "summary",
    )
    for key in scalar_fields:
        if not isinstance(raw[key], str):
            raise RuleCatalogError(f"{path}.{key}: must be a string")
    default_enabled = raw.get("default_enabled")
    if default_enabled is None:
        # Catalog v2 migration: all pre-v2 built-ins are legacy IDs and retain
        # their previous enabled-by-default behavior without a 227-row rewrite.
        # New built-ins must make activation intent explicit.
        if not (builtin and legacy_id):
            raise RuleCatalogError(f"{path}.default_enabled: field is required")
        default_enabled = True
    if not isinstance(default_enabled, bool):
        raise RuleCatalogError(f"{path}.default_enabled: must be a boolean")
    descriptor = RuleDescriptor(
        id=raw["id"],
        language=language,  # type: ignore[arg-type]
        engine=raw["engine"],
        defect_class=raw["defect_class"],
        cwe=raw["cwe"],
        skill=raw["skill"],
        default_severity=raw["default_severity"],
        revision=revision,
        status=raw["status"],
        title=raw["title"],
        summary=raw["summary"],
        required_capabilities=list_fields["required_capabilities"],
        aliases=list_fields["aliases"],
        legacy_id=legacy_id,
        source=source,
        default_enabled=default_enabled,
    )
    RuleCatalog._validate_descriptor(descriptor, validate_builtin_engine=builtin)
    if skill_languages is not None:
        supported = skill_languages.get(descriptor.skill)
        if supported is None:
            raise RuleCatalogError(
                f"{path}.skill: rule {descriptor.id!r} references unknown Skill "
                f"{descriptor.skill!r}"
            )
        if descriptor.language not in supported:
            raise RuleCatalogError(
                f"{path}.skill: Skill {descriptor.skill!r} does not support "
                f"{descriptor.language}"
            )
    return descriptor


def external_descriptor(
    *,
    rule_id: str,
    language: str,
    engine: str,
    defect_class: str,
    cwe: str,
    skill: str,
    severity: str,
    title: str,
    summary: str,
    source: str,
    revision: int = 1,
    status: str = "stable",
    required_capabilities: Sequence[str] = ("source_text",),
    aliases: Sequence[str] = (),
    default_enabled: bool = True,
) -> RuleDescriptor:
    descriptor = RuleDescriptor(
        id=rule_id,
        language=language,  # type: ignore[arg-type]
        engine=engine,
        defect_class=defect_class,
        cwe=cwe,
        skill=skill,
        default_severity=severity,
        revision=revision,
        status=status,
        title=title,
        summary=summary,
        required_capabilities=tuple(required_capabilities),
        aliases=tuple(aliases),
        legacy_id=False,
        source=source,
        default_enabled=default_enabled,
    )
    RuleCatalog._validate_descriptor(descriptor)
    if descriptor.id.startswith("zscope."):
        raise RuleCatalogError(
            f"external rule {descriptor.id!r} cannot use the reserved 'zscope.' namespace"
        )
    if descriptor.engine not in EXTENSION_ENGINES:
        raise RuleCatalogError(
            f"external rule {descriptor.id!r} has invalid engine {descriptor.engine!r}"
        )
    return descriptor


def packaged_skill_languages() -> Mapping[str, Sequence[str]]:
    from ..orchestration.specs import SpecRegistry

    registry = SpecRegistry()
    return {
        name: tuple(getattr(spec, "languages", ()) or ()) for name, spec in registry.skills.items()
    }


def _nearest(value: str, candidates: Iterable[str]) -> str:
    import difflib

    matches = difflib.get_close_matches(value, sorted(candidates), n=1, cutoff=0.55)
    return matches[0] if matches else ""


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

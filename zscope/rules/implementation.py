"""Production consistency checks for built-in deterministic rule implementations.

The catalog is the metadata authority, but a descriptor is only useful when a
detector can actually emit its ID.  This module inventories the finite IDs that
are statically discoverable from the built-in engines and rejects catalog/code
drift during rule preflight.  Discovery is cached by a digest of the inspected
source files, so every ingress gets the same check without repeatedly parsing
the candidate modules.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Dict, Iterable, Mapping, MutableMapping, Sequence, Set, Tuple

from .catalog import BUILTIN_ENGINES, RuleCatalog, RuleCatalogError


_CPP_ENGINE_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("Regex", "cpp_regex"),
    ("Clang", "cpp_clang_cfg"),
    ("Graph", "cpp_graph"),
)
_CPP_FACADES: Tuple[str, ...] = ("regex.py", "clang_ast_cfg.py", "graph.py")
_MATCHER_SOURCE = "retrieval/clang_tooling_evidence.py"
_INTERNAL_MATCHER_FACT_IDS = frozenset(
    {
        # These are intermediate acquire/release observations.  The adapter
        # emits the governed resource-balance rule after pairing them.
        "clang_ast_resource_acquire_call",
        "clang_ast_resource_release_call",
    }
)
_ALLOWED_UNRESOLVED_RULE_EXPRESSIONS = frozenset(
    {
        # The regex facade binds the concrete ID supplied by each domain
        # detector.  Those call sites are inventoried independently.
        ("cpp_regex", "_make_emit", "rule"),
    }
)


@dataclass(frozen=True)
class BuiltinImplementationInventory:
    """Immutable snapshot of rule IDs and Java metadata found in source."""

    rule_ids_by_engine: Mapping[str, Tuple[str, ...]]
    java_metadata: Tuple[Tuple[str, str, str, str], ...]
    source_sha256: str

    def ids_for(self, engine: str) -> frozenset[str]:
        return frozenset(self.rule_ids_by_engine.get(engine, ()))

    @property
    def signature(self) -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
        return tuple(
            (engine, tuple(self.rule_ids_by_engine.get(engine, ())))
            for engine in sorted(BUILTIN_ENGINES)
        )


def discover_builtin_implementation() -> BuiltinImplementationInventory:
    """Return the cached inventory for the currently installed source tree."""

    root = Path(__file__).resolve().parents[1]
    sources = _implementation_sources(root)
    digest = _source_digest(root, sources)
    return _discover_cached(str(root), digest)


def validate_builtin_implementation(catalog: RuleCatalog) -> None:
    """Fail when built-in detector IDs or Java metadata drift from ``catalog``."""

    inventory = discover_builtin_implementation()
    expected = tuple(
        (
            engine,
            tuple(sorted(item.id for item in catalog if item.engine == engine)),
        )
        for engine in sorted(BUILTIN_ENGINES)
    )
    expected_java_metadata = tuple(
        sorted(
            (item.id, item.defect_class, item.cwe, item.skill)
            for item in catalog
            if item.engine == "java_local"
        )
    )
    _validate_cached(
        expected,
        inventory.signature,
        expected_java_metadata,
        inventory.java_metadata,
    )


def clear_builtin_implementation_cache() -> None:
    """Clear source/validation caches for tests and in-process developer reloads."""

    _discover_cached.cache_clear()
    _validate_cached.cache_clear()


def _implementation_sources(root: Path) -> Tuple[Path, ...]:
    candidate_root = root / "core" / "candidates"
    domain_root = candidate_root / "cpp_domains"
    sources = [candidate_root / name for name in _CPP_FACADES]
    sources.extend(sorted(domain_root.glob("*.py")))
    sources.extend((candidate_root / "java_rules.py", root / _MATCHER_SOURCE))
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        raise RuleCatalogError(
            "built-in rule implementation source is missing: " + ", ".join(missing)
        )
    return tuple(sources)


def _source_digest(root: Path, sources: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for path in sources:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


@lru_cache(maxsize=4)
def _discover_cached(root_text: str, source_sha256: str) -> BuiltinImplementationInventory:
    root = Path(root_text)
    del source_sha256  # It is the cache identity; source bytes are parsed below.
    candidate_root = root / "core" / "candidates"
    methods_by_engine: Dict[str, Dict[str, ast.FunctionDef]] = {
        "cpp_regex": {},
        "cpp_clang_cfg": {},
        "cpp_graph": {},
    }
    cpp_sources = [candidate_root / name for name in _CPP_FACADES]
    cpp_sources.extend(sorted((candidate_root / "cpp_domains").glob("*.py")))
    for path in cpp_sources:
        tree = _parse_source(path)
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            engine = next(
                (
                    candidate
                    for prefix, candidate in _CPP_ENGINE_PREFIXES
                    if node.name.startswith(prefix)
                ),
                None,
            )
            if engine is None:
                continue
            for item in node.body:
                if not isinstance(item, ast.FunctionDef):
                    continue
                previous = methods_by_engine[engine].get(item.name)
                if previous is not None:
                    raise RuleCatalogError(
                        f"duplicate built-in {engine} detector method {item.name!r}"
                    )
                methods_by_engine[engine][item.name] = item

    ids_by_engine: Dict[str, Tuple[str, ...]] = {}
    for engine, methods in methods_by_engine.items():
        ids_by_engine[engine] = tuple(sorted(_discover_rule_keywords(engine, methods)))

    matcher_tree = _parse_source(root / _MATCHER_SOURCE)
    matcher_ids = _discover_matcher_ids(matcher_tree) - _INTERNAL_MATCHER_FACT_IDS
    ids_by_engine["cpp_clang_matcher"] = tuple(sorted(matcher_ids))

    # Importing this local table is side-effect free: it compiles regex objects
    # but does not create a CodeIndex, invoke a tool, or call an LLM.
    from ..core.candidates.java_rules import JavaRuleCandidateGenerator

    java_metadata = tuple(
        (rule.rule_id, rule.defect_class, rule.cwe, rule.skill)
        for rule in JavaRuleCandidateGenerator._RULES
    )
    ids_by_engine["java_local"] = tuple(sorted(item[0] for item in java_metadata))
    return BuiltinImplementationInventory(
        rule_ids_by_engine=MappingProxyType(dict(ids_by_engine)),
        java_metadata=java_metadata,
        source_sha256=_source_digest(root, _implementation_sources(root)),
    )


def _parse_source(path: Path) -> ast.Module:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise RuleCatalogError(
            f"cannot inspect built-in rule implementation {path}: {exc}"
        ) from exc


def _discover_rule_keywords(
    engine: str,
    methods: Mapping[str, ast.FunctionDef],
) -> Set[str]:
    parameter_values: Dict[str, Dict[str, Set[str]]] = {
        name: {parameter: set() for parameter in _parameters(method)}
        for name, method in methods.items()
    }

    # Resolve finite IDs passed through helper method parameters.  This is
    # required for shared emitters while keeping their concrete call sites the
    # implementation authority.
    for _ in range(max(1, len(methods) + 1)):
        changed = False
        for name, method in methods.items():
            environment = _local_string_environment(method, parameter_values[name])
            for call in (item for item in ast.walk(method) if isinstance(item, ast.Call)):
                function = call.func
                if (
                    not isinstance(function, ast.Attribute)
                    or not isinstance(function.value, ast.Name)
                    or function.value.id not in {"self", "cls"}
                    or function.attr not in methods
                ):
                    continue
                callee = function.attr
                positional = _parameters(methods[callee])
                for parameter, expression in zip(positional, call.args):
                    changed |= _merge_values(
                        parameter_values[callee],
                        parameter,
                        _static_strings(expression, environment),
                    )
                for keyword in call.keywords:
                    if keyword.arg:
                        changed |= _merge_values(
                            parameter_values[callee],
                            keyword.arg,
                            _static_strings(keyword.value, environment),
                        )
        if not changed:
            break

    discovered: Set[str] = set()
    unresolved = []
    for name, method in methods.items():
        environment = _local_string_environment(method, parameter_values[name])
        for call in (item for item in ast.walk(method) if isinstance(item, ast.Call)):
            for keyword in call.keywords:
                if keyword.arg != "rule":
                    continue
                values = _static_strings(keyword.value, environment)
                if values:
                    discovered.update(values)
                    continue
                expression_text = ast.unparse(keyword.value)
                if (
                    engine,
                    name,
                    expression_text,
                ) not in _ALLOWED_UNRESOLVED_RULE_EXPRESSIONS:
                    unresolved.append(f"{engine}.{name}: {expression_text}")
    if unresolved:
        raise RuleCatalogError(
            "built-in rule ID is not statically finite: " + "; ".join(sorted(unresolved))
        )
    return discovered


def _parameters(method: ast.FunctionDef) -> Tuple[str, ...]:
    values = tuple(
        item.arg
        for item in (
            *method.args.posonlyargs,
            *method.args.args,
            *method.args.kwonlyargs,
        )
    )
    return values[1:] if values and values[0] in {"self", "cls"} else values


def _local_string_environment(
    method: ast.FunctionDef,
    parameters: Mapping[str, Set[str]],
) -> Dict[str, Set[str]]:
    environment = {name: set(values) for name, values in parameters.items()}
    named_sequences: Dict[str, ast.expr] = {}
    for item in ast.walk(method):
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    named_sequences[target.id] = item.value

    for _ in range(max(2, len(named_sequences) + 1)):
        changed = False
        for item in ast.walk(method):
            if isinstance(item, ast.Assign):
                values = _static_strings(item.value, environment)
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        changed |= _merge_values(environment, target.id, values)
            elif (
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.value is not None
            ):
                changed |= _merge_values(
                    environment,
                    item.target.id,
                    _static_strings(item.value, environment),
                )
            elif isinstance(item, ast.For):
                sequence = item.iter
                if isinstance(sequence, ast.Name):
                    sequence = named_sequences.get(sequence.id, sequence)
                changed |= _merge_destructured_loop(environment, item.target, sequence)
        if not changed:
            break
    return environment


def _merge_destructured_loop(
    environment: MutableMapping[str, Set[str]],
    target: ast.expr,
    sequence: ast.expr,
) -> bool:
    if not isinstance(target, (ast.Tuple, ast.List)):
        return False
    if not isinstance(sequence, (ast.Tuple, ast.List)):
        return False
    changed = False
    for row in sequence.elts:
        if not isinstance(row, (ast.Tuple, ast.List)) or len(row.elts) != len(target.elts):
            continue
        for target_item, value_item in zip(target.elts, row.elts):
            if isinstance(target_item, ast.Name):
                changed |= _merge_values(
                    environment,
                    target_item.id,
                    _static_strings(value_item, environment),
                )
    return changed


def _static_strings(
    expression: ast.AST,
    environment: Mapping[str, Set[str]],
) -> Set[str]:
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return {expression.value}
    if isinstance(expression, ast.Name):
        return set(environment.get(expression.id, ()))
    if isinstance(expression, ast.IfExp):
        return _static_strings(expression.body, environment) | _static_strings(
            expression.orelse, environment
        )
    if isinstance(expression, ast.JoinedStr):
        resolved = {""}
        for part in expression.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                values = {part.value}
            elif isinstance(part, ast.FormattedValue):
                values = _static_strings(part.value, environment)
            else:
                return set()
            if not values:
                return set()
            resolved = {prefix + value for prefix in resolved for value in values}
        return resolved
    return set()


def _merge_values(
    target: MutableMapping[str, Set[str]],
    name: str,
    values: Iterable[str],
) -> bool:
    destination = target.setdefault(name, set())
    additions = set(values) - destination
    destination.update(additions)
    return bool(additions)


def _discover_matcher_ids(tree: ast.Module) -> Set[str]:
    result: Set[str] = set()
    for item in ast.walk(tree):
        if isinstance(item, ast.Call):
            function_name = (
                item.func.attr
                if isinstance(item.func, ast.Attribute)
                else item.func.id if isinstance(item.func, ast.Name) else ""
            )
            if function_name == "_matcher_fact" and item.args:
                result.update(_static_strings(item.args[0], {}))
        elif isinstance(item, ast.Dict):
            for key, value in zip(item.keys, item.values):
                if isinstance(key, ast.Constant) and key.value == "rule_id" and value is not None:
                    result.update(_static_strings(value, {}))
    return result


@lru_cache(maxsize=16)
def _validate_cached(
    expected: Tuple[Tuple[str, Tuple[str, ...]], ...],
    actual: Tuple[Tuple[str, Tuple[str, ...]], ...],
    expected_java_metadata: Tuple[Tuple[str, str, str, str], ...],
    java_metadata: Tuple[Tuple[str, str, str, str], ...],
) -> None:
    expected_by_engine = {engine: set(ids) for engine, ids in expected}
    actual_by_engine = {engine: set(ids) for engine, ids in actual}
    problems = []
    for engine in sorted(BUILTIN_ENGINES):
        missing_implementation = sorted(
            expected_by_engine.get(engine, set()) - actual_by_engine.get(engine, set())
        )
        unregistered_implementation = sorted(
            actual_by_engine.get(engine, set()) - expected_by_engine.get(engine, set())
        )
        if missing_implementation:
            problems.append(
                f"{engine} catalog IDs without implementation: " + ", ".join(missing_implementation)
            )
        if unregistered_implementation:
            problems.append(
                f"{engine} implementation IDs missing from catalog: "
                + ", ".join(unregistered_implementation)
            )

    java_ids = [item[0] for item in java_metadata]
    duplicate_java = sorted({item for item in java_ids if java_ids.count(item) > 1})
    if duplicate_java:
        problems.append("java_local duplicate implementation IDs: " + ", ".join(duplicate_java))
    expected_java = {item[0]: item[1:] for item in expected_java_metadata}
    for rule_id, defect_class, cwe, skill in java_metadata:
        expected_metadata = expected_java.get(rule_id)
        actual_metadata = (defect_class, cwe, skill)
        if expected_metadata is not None and actual_metadata != expected_metadata:
            problems.append(
                f"{rule_id}: implementation metadata {actual_metadata!r} "
                f"!= catalog {expected_metadata!r}"
            )
    if problems:
        raise RuleCatalogError(
            "built-in rule implementation/catalog mismatch: " + "; ".join(problems)
        )

"""Versioned deterministic facts used by candidate identity and validation.

The candidate pipeline deliberately keeps this module independent from the LLM
and report layers.  It turns already collected AST/CFG, value-flow, ownership,
concurrency and contract evidence into small, immutable facts.  Missing facts
remain missing; this module never infers safety from prose or from a model
verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import asdict, dataclass
from threading import RLock
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence


DECISION_FACT_VERSION = "zscope.decision-facts.v1.1"
SECURITY_OBLIGATION_VERSION = "zscope.security-obligation.v1.1"
DECISION_CONTEXT_V31 = "zscope.decision-context.v3.1"
DECISION_CONTEXT_V32 = "zscope.decision-context.v3.2"

_SHAPES = {"source_centric", "sink_sensitive", "path_sensitive"}
SUPPORTED_DECISION_FACT_RELATIONS = frozenset(
    {
        # Control flow.
        "dominates",
        "post_dominates",
        "reaches",
        "mutually_exclusive",
        # Data flow.
        "flows_to",
        "sanitized_by",
        "bounded_by",
        "derived_from",
        # Object lifetime.
        "aliases",
        "field_of",
        "transfers_to",
        "released_by",
        # Concurrency.
        "protected_by",
        "held_at",
        "happens_before",
        "conflicts_with",
        # Calls and contracts.
        "calls",
        "returns_to",
        "requires_contract",
        "ensures_contract",
    }
)
_SOURCE_CENTRIC_LEGACY_RULES = {
    "clang_cfg_allocation_result_used_without_null_check",
    "clang_cfg_alloc_result_deref_without_null_guard",
    "clang_cfg_acquire_without_release_on_exit",
    "clang_cfg_unlock_without_matching_lock",
    "clang_cfg_return_with_lock_held",
}
# This is a semantic obligation contract, not a detector-name allow-list.
# These questions are about one acquisition or one lock protocol; later use
# sites are provenance unless their guard/ownership facts differ.  UAF,
# double-free, bounds and command sinks deliberately remain sink-sensitive.
_SOURCE_CENTRIC_DEFECT_TOKENS = {
    "unchecked_allocation",
    "null_pointer_dereference",
    "memory_leak",
    "resource_leak",
    "fd_leak",
    "file_descriptor_leak",
    "missing_unlock",
    "unlock_without_matching_lock",
    "return_with_lock_held",
    "lock_leak",
}


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))


def _digest(value: Any, length: int = 32) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:length]


def normalize_path(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    return text


def normalize_subject(value: Any) -> str:
    """Return a field-sensitive object identity, never a display-only name."""

    if isinstance(value, Mapping):
        for key in ("access_path", "field_path", "resource", "object", "variable", "name", "expression"):
            if value.get(key) not in (None, ""):
                value = value[key]
                break
    text = re.sub(r"\s+", "", str(value or ""))
    text = text.lstrip("*&")
    text = text.replace("->", ".")
    text = re.sub(r"\[.*?\]", "[]", text)
    return text.lower()


def _fact_subject_uid(value: Any, *, function_uid: str) -> str:
    """Give locals a scope-qualified identity while preserving field paths.

    A bare name such as ``buffer`` is not a project-stable object identity.
    The fact graph is nevertheless allowed to represent a local object when
    the producer has no richer access path, as long as the name is bound to
    the exact function identity.  Field paths stay field-sensitive (for
    example ``session->buffer.data`` becomes ``session.buffer.data``).
    """

    subject = normalize_subject(value)
    if not subject:
        return ""
    if "." in subject or "[]" in subject:
        return subject
    return f"local:{function_uid}:{subject}"


def _mapping(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _values(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value] if value not in (None, "", {}, []) else []


def _decision_code_hash(
    issue: Mapping[str, Any],
    pack: Mapping[str, Any],
    ast_cfg: Mapping[str, Any],
) -> str:
    """Return an auditable hash for the exact source evidence being decided.

    Detectors did not consistently carry a repository fingerprint into the
    report.  Treating that absence as an empty hash made otherwise complete
    AST/CFG facts unusable for a proof and, worse, gave the same blank
    dependency identity to unrelated candidates.  Prefer a producer supplied
    source hash; otherwise hash the stable source snapshot that was actually
    supplied to the detector.  The final structured fallback is deliberately
    scoped to the function/range/events, so it cannot silently identify two
    different functions as the same code.
    """

    for value in (
        issue.get("dependency_code_hash"),
        issue.get("code_hash"),
        issue.get("source_fingerprint"),
        pack.get("dependency_code_hash"),
        pack.get("code_hash"),
        pack.get("source_fingerprint"),
        _mapping(ast_cfg.get("clang_tooling")).get("source_fingerprint"),
    ):
        text = str(value or "").strip()
        if text:
            return text

    snippet = str(
        issue.get("code_snippet")
        or issue.get("source_snippet")
        or pack.get("code_snippet")
        or ""
    ).strip()
    function = str(
        issue.get("function_signature")
        or issue.get("function")
        or _mapping(pack.get("path")).get("function")
        or ""
    )
    file_path = normalize_path(issue.get("file") or issue.get("file_path"))
    if snippet:
        return "SNAP_" + _digest(
            {"file": file_path, "function": function, "snippet": snippet},
            length=64,
        )

    # This fallback is still a hash of concrete extractor output, not a
    # display description or LLM text.  It is marked as a snapshot hash and
    # remains invalidated whenever the extractor's range/events change.
    return "SNAP_" + _digest(
        {
            "file": file_path,
            "function": function,
            "range": _mapping(ast_cfg.get("clang_tooling")).get("range"),
            "events": ast_cfg.get("events") or (),
            "guards": ast_cfg.get("condition_guards") or (),
        },
        length=64,
    )


@dataclass(frozen=True)
class DecisionFact:
    fact_uid: str
    fact_kind: str
    subject_uid: str
    function_uid: str
    cfg_node_uid: str
    producer_engine: str
    polarity: str
    attributes: Mapping[str, Any]
    code_hash: str
    completeness: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DecisionFactEdge:
    edge_uid: str
    source_fact_uid: str
    relation: str
    target_fact_uid: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DecisionFactSlice:
    obligation_uid: str
    fact_uids: tuple[str, ...]
    edge_uids: tuple[str, ...]
    dependency_code_hashes: tuple[str, ...]
    coverage: str
    missing_fact_kinds: tuple[str, ...]
    assumptions: tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SecurityObligation:
    obligation_uid: str
    defect_family: str
    obligation_shape: str
    subject_uid: str
    source_uid: str
    sink_uid: str
    decision_region_uid: str
    required_fact_kinds: tuple[str, ...]
    decision_fact_slice: Optional[DecisionFactSlice] = None
    version: str = SECURITY_OBLIGATION_VERSION

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.decision_fact_slice is not None:
            data["decision_fact_slice"] = self.decision_fact_slice.to_dict()
        return data


class DecisionFactGraph:
    """Immutable project-scoped collection of deterministic decision facts."""

    def __init__(
        self,
        facts: Iterable[DecisionFact] = (),
        edges: Iterable[DecisionFactEdge] = (),
        *,
        project_id: str = "",
        revision: str = "",
        index_epoch: str = "",
        source_fingerprint: str = "",
    ) -> None:
        self.project_id = str(project_id or "")
        self.revision = str(revision or "")
        self.index_epoch = str(index_epoch or "")
        self.source_fingerprint = str(source_fingerprint or "")
        self.facts = tuple(sorted(facts, key=lambda item: item.fact_uid))
        self.edges = tuple(sorted(edges, key=lambda item: item.edge_uid))
        self._by_kind = {}
        for fact in self.facts:
            self._by_kind.setdefault(fact.fact_kind, []).append(fact)

    @property
    def cache_key(self) -> str:
        return "FACTS_" + _digest(
            {
                "version": DECISION_FACT_VERSION,
                "project": self.project_id,
                "revision": self.revision,
                "index_epoch": self.index_epoch,
                "source_fingerprint": self.source_fingerprint,
            },
            length=48,
        )

    @classmethod
    def from_issue(cls, issue: Mapping[str, Any]) -> "DecisionFactGraph":
        pack = _mapping(issue.get("evidence_pack"))
        ast_cfg = _mapping(pack.get("ast_cfg"))
        path = _mapping(pack.get("path"))
        value = _mapping(pack.get("value_flow") or pack.get("value_range"))
        ownership = _mapping(pack.get("ownership") or pack.get("resource_typestate"))
        concurrency = _mapping(pack.get("concurrency"))
        contract = _mapping(pack.get("contract") or pack.get("cross_procedure_contract"))
        code_hash = _decision_code_hash(issue, pack, ast_cfg)
        function = str(
            issue.get("function_signature")
            or issue.get("function")
            or path.get("function")
            or issue.get("entry_function")
            or ""
        )
        file_path = normalize_path(issue.get("file") or issue.get("file_path") or path.get("file"))
        function_uid = "FUNC_" + _digest({"file": file_path, "signature": function})
        complete = bool(path.get("complete_in_function") is True or path.get("complete") is True)
        collection_failed = bool(
            issue.get("decision_fact_collection_failed")
            or pack.get("decision_fact_collection_failed")
            or pack.get("decision_fact_collection_error")
        )
        completeness = "failed" if collection_failed else "complete" if complete else "partial"
        facts: list[DecisionFact] = []
        edges: list[DecisionFactEdge] = []

        def add_fact(
            kind: str,
            *,
            subject: Any = "",
            node: Any = "",
            polarity: str = "positive",
            attributes: Optional[Mapping[str, Any]] = None,
            producer: str = "ast_cfg",
            fact_completeness: str = completeness,
        ) -> DecisionFact:
            normalized_subject = _fact_subject_uid(subject, function_uid=function_uid)
            cfg_node_uid = "CFG_" + _digest({"function": function_uid, "node": str(node or "")})
            payload = {
                "version": DECISION_FACT_VERSION,
                "kind": kind,
                "subject": normalized_subject,
                "function": function_uid,
                "cfg": cfg_node_uid,
                "polarity": polarity,
                "attributes": dict(attributes or {}),
                "code_hash": code_hash,
                "completeness": fact_completeness,
            }
            fact = DecisionFact(
                fact_uid="FACT_" + _digest(payload),
                fact_kind=kind,
                subject_uid=normalized_subject,
                function_uid=function_uid,
                cfg_node_uid=cfg_node_uid,
                producer_engine=producer,
                polarity=polarity,
                attributes=dict(attributes or {}),
                code_hash=code_hash,
                completeness=fact_completeness,
            )
            if fact not in facts:
                facts.append(fact)
            return fact

        event_facts: list[DecisionFact] = []
        for event in ast_cfg.get("events") or []:
            if not isinstance(event, Mapping):
                continue
            kind = str(event.get("kind") or "event").strip().lower()
            subject = event.get("access_path") or event.get("field_path") or event.get("variable") or event.get("object") or event.get("expression")
            event_facts.append(
                add_fact(
                    f"event:{kind}",
                    subject=subject,
                    node=event.get("cfg_node") or event.get("line"),
                    attributes={str(k): v for k, v in event.items() if k not in {"expression"}},
                )
            )

        source_identity = issue.get("source_identity") or issue.get("source") or pack.get("source")
        sink_identity = issue.get("sink_identity") or issue.get("sink") or pack.get("sink")
        if source_identity not in (None, "", {}, []):
            add_fact("source", subject=source_identity, attributes={"identity": source_identity})
        if sink_identity not in (None, "", {}, []):
            add_fact("sink", subject=sink_identity, attributes={"identity": sink_identity})

        for guard in ast_cfg.get("condition_guards") or pack.get("guards") or []:
            guard_data = _mapping(guard)
            condition = guard_data.get("condition") if guard_data else guard
            add_fact(
                "guard",
                subject=guard_data.get("variable") or condition,
                node=guard_data.get("cfg_node") or guard_data.get("line"),
                attributes={"condition": str(condition or ""), "terminating": guard_data.get("terminating")},
            )
        for sanitizer in _values(value.get("sanitizers") or pack.get("sanitizers")):
            add_fact("sanitizer", subject=sanitizer, attributes={"value": sanitizer}, producer="value_flow")
        for constraint in _values(value.get("ranges") or value.get("length_constraints") or pack.get("length_constraints")):
            add_fact("value_range", subject=constraint, attributes={"constraint": constraint}, producer="value_flow")
        for check in _values(value.get("overflow_checks") or pack.get("overflow_checks")):
            add_fact("overflow_check", subject=check, attributes={"check": check}, producer="value_flow")
        for item in _values(ownership.get("aliases")):
            add_fact("alias", subject=item, attributes={"alias": item}, producer="ownership")
        for item in _values(ownership.get("transitions")):
            add_fact("ownership_transition", subject=ownership.get("resource") or issue.get("resource"), attributes={"transition": item}, producer="ownership")
        for item in _values(ownership.get("transfer") or pack.get("ownership_transfer")):
            add_fact("ownership_transfer", subject=ownership.get("resource") or issue.get("resource"), attributes={"transfer": item}, producer="ownership")
        for item in _values(ownership.get("cleanup_paths") or pack.get("cleanup_paths")):
            add_fact("cleanup_path", subject=ownership.get("resource") or issue.get("resource"), attributes={"path": item}, producer="ownership")
        for item in _values(concurrency.get("lockset") or pack.get("lockset")):
            add_fact("lockset", subject=concurrency.get("object") or issue.get("thread_object"), attributes={"lock": item}, producer="concurrency")
        for item in _values(concurrency.get("happens_before") or pack.get("happens_before")):
            add_fact("happens_before", subject=concurrency.get("object") or issue.get("thread_object"), attributes={"edge": item}, producer="concurrency")
        for key, kind in (("preconditions", "contract_precondition"), ("postconditions", "contract_postcondition"), ("error_paths", "error_path"), ("caller_responsibility", "caller_responsibility"), ("cleanup_responsibility", "cleanup_responsibility")):
            for item in _values(contract.get(key) or pack.get(key)):
                add_fact(kind, subject=item, attributes={"value": item}, producer="contract")

        # Explicitly recorded path relationships are the only basis for graph
        # edges.  Nearby lines and prose never create a relation.
        relations = _mapping(pack.get("decision_relations") or path.get("relations"))
        facts_by_kind: Dict[str, list[DecisionFact]] = {}
        for fact in facts:
            facts_by_kind.setdefault(fact.fact_kind, []).append(fact)

        def relation_fact(kind: Any, subject: Any) -> Optional[DecisionFact]:
            candidates = list(facts_by_kind.get(str(kind or ""), ()))
            if subject not in (None, ""):
                subject_uid = _fact_subject_uid(subject, function_uid=function_uid)
                candidates = [fact for fact in candidates if fact.subject_uid == subject_uid]
            # An unqualified relation with multiple source facts is ambiguous.
            # Refusing to create the edge is safer than linking an arbitrary
            # event solely because it appeared last in a dictionary.
            return candidates[0] if len(candidates) == 1 else None

        for relation, pairs in relations.items():
            if str(relation) not in SUPPORTED_DECISION_FACT_RELATIONS:
                continue
            for pair in _values(pairs):
                if not isinstance(pair, Mapping):
                    continue
                source = relation_fact(pair.get("source_kind"), pair.get("source_subject"))
                target = relation_fact(pair.get("target_kind"), pair.get("target_subject"))
                if source is None or target is None:
                    continue
                edge = DecisionFactEdge(
                    edge_uid="EDGE_" + _digest({"source": source.fact_uid, "relation": relation, "target": target.fact_uid}),
                    source_fact_uid=source.fact_uid,
                    relation=str(relation),
                    target_fact_uid=target.fact_uid,
                )
                if edge not in edges:
                    edges.append(edge)
        return cls(
            facts,
            edges,
            project_id=str(issue.get("project_id") or ""),
            revision=str(issue.get("revision") or ""),
            index_epoch=str(issue.get("index_epoch") or pack.get("index_epoch") or ""),
            source_fingerprint=code_hash,
        )

    @classmethod
    def from_issues(
        cls,
        issues: Iterable[Mapping[str, Any]],
        *,
        project_id: str = "",
        revision: str = "",
        index_epoch: str = "",
        source_fingerprint: str = "",
    ) -> "DecisionFactGraph":
        """Build one immutable graph for a project-level candidate batch.

        Candidate collection can run per entry, but every issue in a batch
        shares the same revision/index identity.  Combining fragments here
        removes duplicate extraction work and gives aliases the same graph
        cache key without allowing one issue's display provenance to affect
        another issue's facts.
        """

        fragments = [cls.from_issue(issue) for issue in issues if isinstance(issue, Mapping)]
        facts = {
            fact.fact_uid: fact
            for fragment in fragments
            for fact in fragment.facts
        }
        edges = {
            edge.edge_uid: edge
            for fragment in fragments
            for edge in fragment.edges
        }
        resolved_project = project_id or next(
            (fragment.project_id for fragment in fragments if fragment.project_id),
            "",
        )
        resolved_revision = revision or next(
            (fragment.revision for fragment in fragments if fragment.revision),
            "",
        )
        resolved_epoch = index_epoch or next(
            (fragment.index_epoch for fragment in fragments if fragment.index_epoch),
            "",
        )
        resolved_fingerprint = source_fingerprint or _digest(
            sorted(fragment.source_fingerprint for fragment in fragments if fragment.source_fingerprint),
            length=64,
        )
        return cls(
            facts.values(),
            edges.values(),
            project_id=resolved_project,
            revision=resolved_revision,
            index_epoch=resolved_epoch,
            source_fingerprint=resolved_fingerprint,
        )

    def slice_for(
        self,
        obligation: SecurityObligation,
    ) -> DecisionFactSlice:
        subject = obligation.subject_uid
        selected = [
            fact for fact in self.facts
            if not subject or not fact.subject_uid or fact.subject_uid == subject
        ]
        # Source and sink are decision facts for a sink-sensitive obligation
        # even when their normalized subjects differ from the owned object.
        selected.extend(
            fact
            for fact in self.facts
            if fact.fact_kind in obligation.required_fact_kinds
            and fact not in selected
        )
        if not selected:
            selected = list(self.facts)
        selected_ids = {fact.fact_uid for fact in selected}
        fact_kinds = {fact.fact_kind for fact in selected}
        missing = tuple(sorted(kind for kind in obligation.required_fact_kinds if kind not in fact_kinds))
        if any(fact.completeness == "failed" for fact in selected):
            coverage = "failed"
        elif selected and not missing and all(fact.completeness == "complete" for fact in selected):
            coverage = "complete"
        else:
            coverage = "partial"
        return DecisionFactSlice(
            obligation_uid=obligation.obligation_uid,
            fact_uids=tuple(sorted(selected_ids)),
            edge_uids=tuple(sorted(edge.edge_uid for edge in self.edges if edge.source_fact_uid in selected_ids and edge.target_fact_uid in selected_ids)),
            dependency_code_hashes=tuple(sorted({fact.code_hash for fact in selected if fact.code_hash})),
            coverage=coverage,
            missing_fact_kinds=missing,
            assumptions=(),
        )


class DecisionFactGraphCache:
    """Bounded, thread-safe cache for immutable per-source fact graphs.

    Callers own the cache lifetime.  Parallel scans therefore share one cache
    while unrelated projects and later scans cannot reuse stale facts.
    """

    def __init__(self, max_entries: int = 4096) -> None:
        self.max_entries = max(1, int(max_entries or 4096))
        self._items: "OrderedDict[str, DecisionFactGraph]" = OrderedDict()
        self._lock = RLock()

    @staticmethod
    def key_for(issue: Mapping[str, Any]) -> str:
        pack = _mapping(issue.get("evidence_pack"))
        path = _mapping(pack.get("path"))
        return "FACTS_" + _digest(
            {
                "version": DECISION_FACT_VERSION,
                "project": issue.get("project_id"),
                "revision": issue.get("revision"),
                "index_epoch": issue.get("index_epoch") or pack.get("index_epoch"),
                "source_fingerprint": issue.get("dependency_code_hash")
                or issue.get("code_hash")
                or issue.get("source_fingerprint")
                or pack.get("dependency_code_hash")
                or pack.get("code_hash")
                or pack.get("source_fingerprint"),
                "function": issue.get("function_signature")
                or issue.get("function")
                or path.get("function"),
                # ``DecisionFactGraph.from_issue`` currently receives the
                # structured evidence attached to one candidate.  Do not
                # accidentally reuse that partial slice for a different
                # obligation in the same function merely because its source
                # file is unchanged.  A future project-wide producer can
                # provide an explicit function fact snapshot and safely omit
                # this input signature.
                "fact_input": {
                    "source": issue.get("source_identity") or pack.get("source"),
                    "sink": issue.get("sink_identity") or pack.get("sink"),
                    "resource": issue.get("resource_identity") or pack.get("resource"),
                    "ast_cfg": pack.get("ast_cfg"),
                    "path": pack.get("path"),
                    "ownership": pack.get("ownership") or pack.get("resource_typestate"),
                    "concurrency": pack.get("concurrency"),
                    "contracts": pack.get("contracts"),
                    "relations": pack.get("decision_relations"),
                    "proof_facts": pack.get("proof_facts"),
                },
            },
            length=48,
        )

    def get_or_build(self, issue: Mapping[str, Any]) -> DecisionFactGraph:
        key = self.key_for(issue)
        with self._lock:
            graph = self._items.get(key)
            if graph is not None:
                self._items.move_to_end(key)
                return graph
        graph = DecisionFactGraph.from_issue(issue)
        with self._lock:
            existing = self._items.get(key)
            if existing is not None:
                self._items.move_to_end(key)
                return existing
            self._items[key] = graph
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
            return graph


def obligation_shape_for_issue(issue: Mapping[str, Any]) -> str:
    pack = _mapping(issue.get("evidence_pack"))
    explicit = str(issue.get("obligation_shape") or pack.get("obligation_shape") or "").lower()
    if explicit in _SHAPES:
        return explicit
    rule = str(issue.get("rule") or pack.get("rule") or "").lower()
    if rule in _SOURCE_CENTRIC_LEGACY_RULES:
        return "source_centric"
    defect = str(
        issue.get("defect_class")
        or issue.get("normalized_category")
        or issue.get("subcategory")
        or issue.get("category")
        or pack.get("defect_class")
        or ""
    ).lower()
    if defect in _SOURCE_CENTRIC_DEFECT_TOKENS:
        return "source_centric"
    # Existing detectors predate the explicit contract.  Their conservative
    # compatibility shape is sink-sensitive, which preserves detector-neutral
    # v3 identity.  New path-sensitive detectors must state the shape in their
    # structured evidence rather than relying on a rule-name heuristic.
    return "sink_sensitive"


def required_fact_kinds_for_issue(issue: Mapping[str, Any]) -> tuple[str, ...]:
    pack = _mapping(issue.get("evidence_pack"))
    explicit = issue.get("obligation_required_fact_kinds") or pack.get("obligation_required_fact_kinds")
    if isinstance(explicit, Sequence) and not isinstance(explicit, str):
        return tuple(sorted({str(item) for item in explicit if str(item)}))
    rule = str(issue.get("rule") or pack.get("rule") or "").lower()
    defect = str(issue.get("defect_class") or issue.get("category") or "").lower()
    text = f"{rule} {defect}"
    if any(token in text for token in ("race", "lock", "thread", "concurr")):
        return ("event:shared_state_access", "lockset")
    if any(token in text for token in ("leak", "release", "acquire", "ownership", "free")):
        return ("event:acquire", "event:exit")
    if any(token in text for token in ("overflow", "bound", "length", "size", "index")):
        return ("source", "sink")
    return ()


def _canonical_source_for_obligation(
    issue: Mapping[str, Any],
    *,
    defect_family: str,
    subject_uid: str,
    fallback_source_uid: str,
) -> str:
    """Return the acquisition/owner/lock fact that owns a source obligation.

    Source-centric findings are commonly emitted once per use site.  A use
    site is provenance, not the security decision: for example, ten uses of
    one allocation guarded by the same failure branch must share a validation
    group.  Pick only a source-derived event from the immutable fact payload;
    descriptions and entry/call-path metadata are intentionally unavailable
    here.  If the detector supplied no such fact, retain its original source
    identity instead of guessing that two candidates are equivalent.
    """

    pack = _mapping(issue.get("evidence_pack"))
    ast_cfg = _mapping(pack.get("ast_cfg"))
    events = [item for item in ast_cfg.get("events") or [] if isinstance(item, Mapping)]
    defect = str(defect_family or "").lower()
    if any(token in defect for token in ("lock", "unlock")):
        source_kinds = ("lock", "acquire_lock", "caller_held_lock")
    elif any(token in defect for token in ("leak", "allocation", "null_pointer")):
        source_kinds = (
            "acquire",
            "allocation",
            "allocation_result",
            "fd_open",
            "resource_open",
            "owner_init",
        )
    else:
        source_kinds = ()

    normalized_subject = normalize_subject(subject_uid)
    ranked: list[tuple[int, str, str]] = []
    for event in events:
        kind = str(event.get("kind") or "").strip().lower()
        if source_kinds and kind not in source_kinds:
            continue
        event_subject = normalize_subject(
            event.get("access_path")
            or event.get("field_path")
            or event.get("variable")
            or event.get("object")
        )
        # A detector may only know the owner field while an event records the
        # local temporary.  Do not merge those without a matching fact.
        if normalized_subject and event_subject and event_subject != normalized_subject:
            continue
        try:
            line = int(event.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if kind and (event_subject or normalized_subject):
            ranked.append((line, kind, event_subject or normalized_subject))
    if not ranked:
        return normalize_subject(fallback_source_uid)
    line, kind, identity = sorted(ranked)[0]
    function = normalize_subject(
        issue.get("function_signature") or issue.get("function") or ""
    )
    return f"{function}:{line}:{kind}:{identity}"


def security_obligation_for(
    issue: Mapping[str, Any],
    *,
    project_id: str,
    revision: str,
    defect_family: str,
    source_uid: str,
    sink_uid: str,
    subject_uid: str,
) -> SecurityObligation:
    shape = obligation_shape_for_issue(issue)
    path = _mapping(_mapping(issue.get("evidence_pack")).get("path"))
    ast_cfg = _mapping(_mapping(issue.get("evidence_pack")).get("ast_cfg"))
    guards = ast_cfg.get("condition_guards") or _mapping(issue.get("evidence_pack")).get("guards") or []
    path_constraints = path.get("path_constraints") or _mapping(issue.get("evidence_pack")).get("path_constraints") or []
    region = {
        "function": str(issue.get("function_signature") or issue.get("function") or path.get("function") or ""),
        "source_line": path.get("source_line") or issue.get("source_line"),
        "branch": path.get("decision_region") or issue.get("decision_region"),
        # Guard/branch facts are decision facts for a source-centric resource
        # obligation.  Their absence is represented as an empty tuple, never
        # inferred from a candidate description.
        "guards": guards,
        "constraints": path_constraints,
    }
    if shape != "source_centric":
        region["sink_line"] = path.get("sink_line") or issue.get("sink_line") or issue.get("line")
    canonical_source = (
        _canonical_source_for_obligation(
            issue,
            defect_family=defect_family,
            subject_uid=subject_uid,
            fallback_source_uid=source_uid,
        )
        if shape == "source_centric"
        else normalize_subject(source_uid)
    )
    payload = {
        "version": SECURITY_OBLIGATION_VERSION,
        "project": str(project_id or ""),
        "revision": str(revision or ""),
        "defect_family": str(defect_family or ""),
        "shape": shape,
        "subject": normalize_subject(subject_uid),
        "source": canonical_source,
        "region": region,
    }
    if shape != "source_centric":
        payload["sink"] = normalize_subject(sink_uid)
    return SecurityObligation(
        obligation_uid="OBL_" + _digest(payload),
        defect_family=str(defect_family or ""),
        obligation_shape=shape,
        subject_uid=normalize_subject(subject_uid),
        source_uid=canonical_source,
        sink_uid=normalize_subject(sink_uid),
        decision_region_uid="REGION_" + _digest(region),
        required_fact_kinds=required_fact_kinds_for_issue(issue),
    )


def deterministic_proofs_from_facts(
    issue: Mapping[str, Any],
    obligation: SecurityObligation,
    fact_slice: DecisionFactSlice,
) -> list[Dict[str, Any]]:
    """Derive only proof shapes whose full deterministic preconditions exist.

    The supported shapes deliberately correspond to explicit source-derived
    events.  A detector label, a nearby guard, or a Validator explanation is
    never enough to make a proof.
    """

    pack = _mapping(issue.get("evidence_pack"))
    ast_cfg = _mapping(pack.get("ast_cfg"))
    path = _mapping(pack.get("path"))
    ownership = _mapping(pack.get("ownership") or pack.get("resource_typestate"))
    concurrency = _mapping(pack.get("concurrency"))
    events = [item for item in ast_cfg.get("events") or [] if isinstance(item, Mapping)]
    complete = path.get("complete_in_function") is True or path.get("complete") is True
    code_hash = next(iter(fact_slice.dependency_code_hashes), "")
    if not complete or not code_hash:
        return []
    event_kinds = {
        str(event.get("kind") or "").strip().lower()
        for event in events
    }
    subject = obligation.subject_uid or obligation.source_uid
    fact_ids = list(fact_slice.fact_uids)
    if not fact_ids:
        return []

    def proof(
        outcome: str,
        kind: str,
        facts: Sequence[str],
        summary: str,
        *,
        scope: str = "complete deterministic decision-fact slice",
    ) -> Dict[str, Any]:
        return {
            "outcome": outcome,
            "proof_kind": kind,
            "producer_engine": "decision_fact_graph_v1",
            "proof_version": "zscope.decision-proof.v3",
            "fact_ids": fact_ids,
            "cfg_nodes": sorted({fact_id for fact_id in fact_ids}),
            "subject_identity": subject,
            "code_hash": code_hash,
            "facts": list(facts),
            "completeness": "complete",
            "scope": scope,
            "summary": summary,
        }

    results: list[Dict[str, Any]] = []
    # A signed result crossing an unsigned length boundary is a complete value
    # violation only when all three source-derived events are present.
    if {
        "signed_io_result",
        "signed_to_unsigned_cast",
        "unsigned_length_sink",
    }.issubset(event_kinds):
        results.append(
            proof(
                "confirm",
                "out_of_range_value_reaches_sink",
                ("source_to_sink_complete", "out_of_range_value"),
                "a signed result reaches an unsigned length sink without a terminating range check",
            )
        )

    normalized_events = []
    for event in events:
        try:
            line = int(event.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        normalized_events.append(
            (
                str(event.get("kind") or "").lower(),
                normalize_subject(
                    event.get("access_path")
                    or event.get("field_path")
                    or event.get("variable")
                    or event.get("object")
                ),
                line,
            )
        )
    release_lines = [line for kind, item_subject, line in normalized_events if kind in {"free", "release", "deallocate"} and (not subject or item_subject == subject)]
    deref_lines = [line for kind, item_subject, line in normalized_events if kind in {"deref", "use", "access"} and (not subject or item_subject == subject)]
    if any(release < deref for release in release_lines for deref in deref_lines if release and deref):
        results.append(
            proof(
                "confirm",
                "use_after_free_path",
                ("free_before_use", "source_to_sink_complete"),
                "the same field-sensitive object is released before a reachable use",
            )
        )
    if len({line for line in release_lines if line}) >= 2:
        results.append(
            proof(
                "confirm",
                "double_release_path",
                ("first_release", "second_release", "same_object_path"),
                "the same field-sensitive object is released twice on a complete path",
            )
        )

    if "acquire" in event_kinds and (
        "exit_without_release" in event_kinds or "return_without_release" in event_kinds
    ):
        results.append(
            proof(
                "confirm",
                "missing_cleanup_path",
                ("allocation_reachable", "cleanup_missing"),
                "a successful acquisition reaches an explicit exit without release or transfer",
            )
        )

    shared_accesses = [event for event in normalized_events if event[0] == "shared_state_access"]
    explicit_conflict = bool(
        concurrency.get("conflicting_accesses")
        or pack.get("conflicting_accesses")
        or "conflicting_accesses" in event_kinds
    )
    no_happens_before = bool(
        concurrency.get("no_happens_before") is True
        or pack.get("no_happens_before") is True
        or "no_happens_before" in event_kinds
    )
    if len(shared_accesses) >= 2 and explicit_conflict and no_happens_before:
        results.append(
            proof(
                "confirm",
                "race_without_happens_before",
                ("conflicting_accesses", "no_happens_before"),
                "two conflicting shared-object accesses have no proven happens-before relation",
            )
        )

    # Rejection providers require explicit engine relationships, not merely a
    # guard or cleanup event at a nearby line.
    proof_facts = _mapping(pack.get("proof_facts") or path.get("proof_facts"))
    if proof_facts.get("guard_dominates_sink") is True:
        results.append(
            proof(
                "reject",
                "guard_dominates_sink",
                ("guard_dominates_sink",),
                "an explicit terminating guard dominates the reported sink",
            )
        )
    if proof_facts.get("cleanup_all_paths") is True:
        results.append(
            proof(
                "reject",
                "ownership_cleanup_complete",
                ("cleanup_all_paths",),
                "all successful ownership paths release or transfer the same resource",
            )
        )
    if (
        proof_facts.get("lock_dominates_access") is True
        and proof_facts.get("all_accesses_guarded") is True
    ):
        results.append(
            proof(
                "reject",
                "lock_dominates_access",
                ("lock_dominates_access", "all_accesses_guarded"),
                "the same lock covers every conflicting access in the complete decision scope",
            )
        )
    if ownership.get("cleanup_all_paths") is True:
        results.append(
            proof(
                "reject",
                "ownership_cleanup_complete",
                ("cleanup_all_paths",),
                "ownership evidence records cleanup or transfer on all complete exits",
            )
        )
    return results


def attach_decision_facts(
    issue: Dict[str, Any],
    *,
    obligation: Optional[SecurityObligation] = None,
    graph: Optional[DecisionFactGraph] = None,
) -> SecurityObligation:
    """Attach the v1 fact slice and structured obligation without changing disposition."""

    if obligation is None:
        obligation = security_obligation_for(
            issue,
            project_id=str(issue.get("project_id") or ""),
            revision=str(issue.get("revision") or ""),
            defect_family=str(issue.get("defect_class") or issue.get("category") or ""),
            source_uid=str(issue.get("source_identity") or issue.get("source") or ""),
            sink_uid=str(issue.get("sink_identity") or issue.get("sink") or ""),
            subject_uid=str(issue.get("resource_identity") or issue.get("resource") or issue.get("thread_object") or issue.get("source_identity") or ""),
        )
    graph = graph or DecisionFactGraph.from_issue(issue)
    fact_slice = graph.slice_for(obligation)
    obligation = SecurityObligation(**{**asdict(obligation), "decision_fact_slice": fact_slice})
    proofs = deterministic_proofs_from_facts(issue, obligation, fact_slice)
    if proofs:
        existing = issue.get("deterministic_proofs")
        if not isinstance(existing, list):
            existing = []
            issue["deterministic_proofs"] = existing
        known = {
            (str(item.get("outcome") or ""), str(item.get("proof_kind") or ""))
            for item in existing
            if isinstance(item, Mapping)
        }
        for proof in proofs:
            key = (str(proof.get("outcome") or ""), str(proof.get("proof_kind") or ""))
            if key not in known:
                existing.append(proof)
                known.add(key)
    issue.update(
        {
            "decision_fact_version": DECISION_FACT_VERSION,
            "decision_fact_graph_key": graph.cache_key,
            "decision_fact_slice": fact_slice.to_dict(),
            "decision_fact_coverage": fact_slice.coverage,
            "missing_fact_kinds": list(fact_slice.missing_fact_kinds),
            "obligation_shape": obligation.obligation_shape,
            "obligation_required_fact_kinds": list(obligation.required_fact_kinds),
            "security_obligation": obligation.to_dict(),
            # This is intentionally diagnostic-only during the shadow rollout.
            # Candidate generation remains unchanged until the new obligation
            # contracts demonstrate that no known true positive is lost.
            "candidate_promotion_eligible": (
                fact_slice.coverage == "complete"
                and not fact_slice.missing_fact_kinds
            ),
            "candidate_promotion_reason": (
                "structured_security_obligation_complete"
                if fact_slice.coverage == "complete"
                and not fact_slice.missing_fact_kinds
                else "missing_required_decision_facts"
            ),
            "candidate_promotion_terminal_status": (
                "candidate"
                if fact_slice.coverage == "complete"
                and not fact_slice.missing_fact_kinds
                # During the feature-flag shadow rollout this remains an
                # auditable lead rather than a report-time deletion.  The
                # promotion decision is made once, before ledger insertion.
                else "triage_lead"
            ),
        }
    )
    return obligation

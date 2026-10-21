from __future__ import annotations

from typing import Any, Dict
import json
from pathlib import Path
import re

from .models import PATTERN_MATCH_SCHEMA, PATTERN_SCHEMA, REVIEW_RECORD_SCHEMA
from .identity import CANDIDATE_MATCHABLE_FIELDS

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"


def validate_registered(value: Dict[str, Any]) -> Dict[str, Any]:
    """Validate an instance against the independent Review Memory registry."""
    schema_version = str(value.get("schema_version") or "")
    registry = json.loads((SCHEMA_DIR / "schema-registry.json").read_text(encoding="utf-8"))
    filename = (registry.get("schemas") or {}).get(schema_version)
    if not filename:
        raise ValueError(f"unregistered Review Memory schema: {schema_version}")
    document = json.loads((SCHEMA_DIR / str(filename)).read_text(encoding="utf-8"))
    if document.get("$id") != schema_version:
        raise ValueError(f"Review Memory schema registry drift: {schema_version}")
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return value
    errors = list(jsonschema.Draft202012Validator(document).iter_errors(value))
    if errors:
        raise ValueError(f"{schema_version}: {errors[0].message}")
    return value


def validate_review_record(value: Dict[str, Any]) -> Dict[str, Any]:
    validate_registered(value)
    if value.get("schema_version") != REVIEW_RECORD_SCHEMA:
        raise ValueError("unsupported review record schema")
    for key in ("review_id", "project_id", "finding", "user_rebuttal", "status"):
        if key not in value:
            raise ValueError(f"review record missing {key}")
    if not isinstance(value["finding"], dict):
        raise ValueError("review record finding must be an object")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", str(value["review_id"])):
        raise ValueError("invalid review_id")
    if not str(value.get("project_id") or "").strip():
        raise ValueError("project_id must not be empty")
    return value


def validate_pattern(value: Dict[str, Any]) -> Dict[str, Any]:
    validate_registered(value)
    if value.get("schema_version") != PATTERN_SCHEMA:
        raise ValueError("unsupported pattern schema")
    for key in ("pattern_id", "project_id", "scope", "trigger_features", "status"):
        if key not in value:
            raise ValueError(f"pattern missing {key}")
    if not isinstance(value["trigger_features"], list):
        raise ValueError("pattern trigger_features must be a list")
    if value.get("status") not in {"pending_extraction", "proposal_failed", "proposed", "semantic_only", "advisory", "stale", "disabled", "deprecated", "superseded"}:
        raise ValueError("invalid pattern status")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", str(value["pattern_id"])):
        raise ValueError("invalid pattern_id")
    contract = value.get("match_contract")
    if contract is not None and not isinstance(contract, dict):
        raise ValueError("pattern match_contract must be an object")
    if isinstance(contract, dict):
        if contract.get("schema_version") != "zscope.candidate-stable-fields.v1":
            raise ValueError("unsupported candidate stable-field contract")
        if not isinstance(contract.get("groups"), list):
            raise ValueError("pattern match_contract groups must be a list")
        for group in contract["groups"]:
            if not isinstance(group, dict) or not isinstance(group.get("all"), list):
                raise ValueError("pattern match_contract group must contain all")
            for predicate in group["all"]:
                if not isinstance(predicate, dict) or not predicate.get("path") or predicate.get("operator", "eq") not in {"eq", "contains"}:
                    raise ValueError("invalid candidate stable-field predicate")
                if predicate.get("path") not in CANDIDATE_MATCHABLE_FIELDS:
                    raise ValueError("candidate predicate references a non-matchable field")
    return value


def validate_pattern_match(value: Dict[str, Any]) -> Dict[str, Any]:
    validate_registered(value)
    if value.get("schema_version") != PATTERN_MATCH_SCHEMA:
        raise ValueError("unsupported pattern match schema")
    for key in ("pattern_id", "scan_id", "issue_identity"):
        if key not in value:
            raise ValueError(f"pattern match missing {key}")
    if not isinstance(value["issue_identity"], dict):
        raise ValueError("pattern match issue_identity must be an object")
    for key in ("pattern_id", "scan_id"):
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,240}", str(value[key])):
            raise ValueError(f"invalid pattern match {key}")
    for key in ("token_cost", "tool_cost"):
        if int(value.get(key, 0)) < 0:
            raise ValueError("pattern match costs must be non-negative")
    return value

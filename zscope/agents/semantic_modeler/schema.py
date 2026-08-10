"""Default semantic snapshot schema used by the semantic modeler."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

PROGRAM_GENERATED_SNAPSHOT_FIELDS = (
    "func_name",
    "index_name",
    "file_path",
    "start_line",
    "end_line",
    "signature",
    "snapshot_kind",
    "is_static",
    "is_macro",
)

PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS = (
    "project_callees",
    "external_callees",
    "referenced_globals",
    "referenced_macros",
    "referenced_types",
)

PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS = (
    "project_callees_truncation",
    "external_callees_truncation",
    "unresolved_callees",
    "unresolved_callees_truncation",
    "referenced_globals_truncation",
    "referenced_macros_truncation",
    "unresolved_referenced_types",
    "referenced_types_truncation",
)

LLM_EXCLUDED_SNAPSHOT_FIELDS = (
    *PROGRAM_GENERATED_SNAPSHOT_FIELDS,
    *PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
    *PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS,
    "callees",
    "callees_truncation",
)

EFFECT_CATEGORY_ENUM = [
    "memory",
    "resource",
    "ownership",
    "alias",
    "bounds",
    "shared_state",
    "lock",
    "thread",
    "sync_protocol",
    "io",
    "callback",
    "global_state",
    "registry",
    "other",
]

SUSPICIOUS_POINT_CATEGORY_ENUM = [
    "memory_safety",
    "resource_lifecycle",
    "bounds",
    "integer",
    "string_format",
    "null_error",
    "ownership",
    "concurrency",
    "state_protocol",
    "type_confusion",
    "input_validation",
    "error_handling",
    "global_state",
    "callback",
    "api_contract",
    "other",
]

EXIT_STATE_ENUM = [
    "not_acquired",
    "acquired",
    "partially_initialized",
    "released",
    "still_held",
    "transferred",
    "invalid",
    "not_held",
    "held",
    "not_retained",
    "retained",
    "unchanged",
    "updated",
    "partially_updated",
    "inconsistent",
    "unknown",
]

DEFAULT_FUNCTION_SNAPSHOT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": [
        "func_name",
        "index_name",
        "file_path",
        "start_line",
        "end_line",
        "signature",
        "snapshot_kind",
        "is_static",
        "is_macro",
        "referenced_globals",
        "referenced_macros",
        "referenced_types",
        "summary",
        "parameters",
        "return_values",
        "effects",
        "error_handling",
        "external_callees",
        "suspicious_points",
    ],
    "properties": {
        "func_name": {"type": "string"},
        "index_name": {
            "type": "string",
            "description": "Canonical function index key, for example func_name@file_path:start_line-end_line",
        },
        "file_path": {"type": "string"},
        "start_line": {"type": "integer"},
        "end_line": {"type": "integer"},
        "signature": {"type": "string"},
        "snapshot_kind": {"const": "LLM-modeled"},
        "is_static": {"type": "boolean"},
        "is_macro": {"type": "boolean"},
        "referenced_globals": {
            "type": "array",
            "description": "Program-extracted global symbol references. This is raw evidence, not an LLM summary of global-state effects.",
            "items": {
                "type": "object",
                "required": [
                    "name",
                    "type",
                    "file_path",
                    "line",
                    "storage_class",
                    "qualifiers",
                    "initializer",
                    "access",
                    "reference_lines",
                ],
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"}, 
                    "storage_class": {"enum": ["static","extern","thread_local","global","unknown",]},
                    "qualifiers": {
                        "type": "array",
                        "items": {"enum": ["const","volatile","atomic",]},
                        "uniqueItems": True,
                    },
                    "initializer": {"type": "string"},
                    "access": {"enum": ["read", "write", "read_write", "unknown"]},
                    "reference_lines": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                },
                "additionalProperties": False,
            },
        },
        "referenced_macros": {
            "type": "array",
            "description": "Program-extracted macro references, including the indexed definition observed when the snapshot was built.",
            "items": {
                "type": "object",
                "required": [
                    "macro_index_name",
                    "definition",
                    "is_function_like",
                    "reference_lines",
                ],
                "properties": {
                    "macro_index_name": {"type": "string"},
                    "definition": {"type": "string"},
                    "is_function_like": {"type": "boolean"},
                    "reference_lines": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                },
                "additionalProperties": False,
            },
        },
        "referenced_types": {
            "type": "array",
            "description": "Program-resolved direct project type references with complete definitions.",
            "items": {
                "type": "object",
                "required": [
                    "type_index_name",
                    "kind",
                    "full_definition",
                    "reference_kinds",
                    "reference_lines",
                ],
                "properties": {
                    "type_index_name": {"type": "string"},
                    "kind": {"type": "string"},
                    "full_definition": {"type": "string"},
                    "reference_kinds": {
                        "type": "array",
                        "items": {
                            "enum": [
                                "return",
                                "parameter",
                                "local",
                                "cast",
                                "sizeof",
                                "alignof",
                                "offsetof",
                                "compound_literal",
                                "member_access",
                                "function_pointer",
                            ]
                        },
                        "uniqueItems": True,
                    },
                    "reference_lines": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                },
                "additionalProperties": False,
            },
        },
        "unresolved_referenced_types": {
            "type": "array",
            "minItems": 1,
            "description": "Program-observed direct type references that could not be uniquely resolved.",
            "items": {
                "type": "object",
                "required": ["name", "reference_kinds", "reference_lines", "reason"],
                "properties": {
                    "name": {"type": "string"},
                    "reference_kinds": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "reference_lines": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                    "reason": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        "referenced_types_truncation": {
            "type": "object",
            "required": [
                "truncated",
                "returned",
                "total",
                "definition_bytes_returned",
                "definition_bytes_limit",
            ],
            "properties": {
                "truncated": {"const": True},
                "returned": {"type": "integer"},
                "total": {"type": "integer"},
                "definition_bytes_returned": {"type": "integer"},
                "definition_bytes_limit": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        "referenced_globals_truncation": {
            "type": "object",
            "required": ["truncated", "returned", "total"],
            "properties": {
                "truncated": {"const": True},
                "returned": {"type": "integer"},
                "total": {"type": "integer"},
            },
        },
        "referenced_macros_truncation": {
            "type": "object",
            "required": ["truncated", "returned", "total"],
            "properties": {
                "truncated": {"const": True},
                "returned": {"type": "integer"},
                "total": {"type": "integer"},
            },
        },
        "summary": {"type": "string"},
        "parameters": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "parameter_name",
                    "parameter_type",
                    "meaning",
                    "input_origin",
                ],
                "properties": {
                    "parameter_name": {"type": "string"},
                    "parameter_type": {"type": "string"},
                    "meaning": {"type": "string"},
                    "input_origin": {"enum": ["external","internal","mixed","unknown",]},
                    "nullable": {"enum": ["yes", "no", "unknown", "not_applicable"]},
                    "ownership_effect": {
                        "description": "How the callee treats ownership of a pointer, handle, reference, or resource parameter. Omit for scalar parameters.",
                        "enum": [
                            "borrow",
                            "consume",
                            "retain",
                            "share",
                            "release",
                            "produce",
                            "initialize",
                            "mutate_borrowed",
                            "unknown",
                        ]
                    },
                    "constraints": {
                        "type": "array",
                        "description": "Constraints, invariants, size relationships, valid ranges, or caller requirements for this parameter. Omit when no constraint exists.",
                        "items": {"type": "string"},
                    },
                },
            },
        },
        "return_values": {
            "type": "object",
            "description": "Caller-visible return value contract. For void functions, set return_type to void and omit all the other fields.",
            "required": [
                "return_type",
            ],
            "properties": {
                "return_type": {"type": "string"},
                "meaning": {"type": "string"},
                "nullable": {"enum": ["yes", "no", "unknown", "not_applicable"]},
                "ownership": {
                    "description": "Ownership state after return for a pointer, handle, reference, or resource value. Omit for void or scalar return types.",
                    "enum": [
                        "caller_owned",
                        "borrowed",
                        "shared",
                        "static_storage",
                        "unknown",
                    ]
                },
                "success_cases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["value", "condition"],
                        "properties": {
                            "value": {"type": "string"},
                            "condition": {"type": "string"},
                        },
                    },
                },
                "failure_cases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["value", "condition"],
                        "properties": {
                            "value": {"type": "string"},
                            "condition": {"type": "string"},
                        },
                    },
                },
                "caller_obligations": {
                    "type": "string",
                    "description": "Additional caller actions required by the return contract. Omit when no additional obligation exists.",
                },
            },
        },
        "effects": {
            "type": "array",
            "description": (
                "Unified effect facts covering memory, resources, ownership, bounds, shared state, locks, threads, IO, callbacks, and global state. "
                "Use an empty array when the function has no observable effects."
            ),
            "items": {
                "type": "object",
                "required": [
                    "category",
                    "description",
                    "line",
                    "object",
                ],
                "properties": {
                    "category": {"enum": EFFECT_CATEGORY_ENUM},
                    "description": {"type": "string"},
                    "line": {"type": ["integer", "null"]},
                    "object": {"type": "string"},
                    "api": {"type": "string"},
                    "condition": {"type": "string"},
                    "state_before": {"type": "string"},
                    "state_after": {"type": "string"},
                    "related_parameters": {"type": "array", "items": {"type": "string"}},
                    "guard": {
                        "type": "string",
                        "description": (
                            "Protections of this effect such as a held lock, bounds or null check, reference-count requirement, object-state precondition, "
                            "or protocol phase constraint. Omit when no guard applies or no guard can be established."
                        ),
                    },
                    "details": {
                        "type": "object",
                        "description": (
                            "Optional category-specific structured evidence that has no equivalent standard effect field. The object may be empty. "
                            "Do not duplicate object, api, line, condition, state_before, state_after, or guard. "
                            "Suggested keys by category: "
                            "memory: size_expression, count_expression, allocation_kind, alignment, failure_value; "
                            "resource: resource_kind, success_value, failure_value, flags; "
                            "ownership: owner_before, owner_after, transfer_kind, lifetime_requirement; "
                            "alias: source, target, alias_kind, escape_scope; "
                            "bounds: operation_kind, size_expression, capacity_expression, validation_status; "
                            "shared_state: access_kind, shared_scope; "
                            "lock: lock_kind, lock_order, recursive; "
                            "thread: entry_function, execution_context, shared_objects, lifetime_requirement; "
                            "sync_protocol: protocol_kind, atomic_operation, reference_delta, expected_state; "
                            "io: direction, endpoint, byte_count_expression, blocking; "
                            "callback: target_function, execution_context, reentrant, lifetime_requirement; "
                            "global_state: access_kind; "
                            "registry: operation_kind, key, value, replacement_behavior."
                        ),
                    },
                },
            },
        },
        "error_handling": {
            "type": "object",
            "description": "Error path summary for this function. Use an empty error_paths array when no error path exists.",
            "required": ["error_paths"],
            "properties": {
                "error_paths": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "trigger",
                            "exit_line",
                            "exit_action",
                        ],
                        "properties": {
                            "trigger": {"type": "string"},
                            "exit_line": {"type": ["integer", "null"]},
                            "exit_action": {"type": "string"},
                            "exit_states": {
                                "type": "array",
                                "description": (
                                    "Final states of memory objects, resources, locks, references, or state variables relevant to this error path. "
                                    "Omit when no relevant object has a path-specific exit state."
                                ),
                                "items": {
                                    "type": "object",
                                    "required": ["kind", "object", "state"],
                                    "properties": {
                                        "kind": {"enum": ["memory", "resource", "lock", "reference", "state", "other"]},
                                        "object": {"type": "string"},
                                        "state": {"enum": EXIT_STATE_ENUM},
                                        "owner": {"type": "string"},
                                    },
                                },
                            },
                            "return_value": {"type": "string"},
                        },
                    },
                },
            },
        },
        "callers": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "caller_index_name",
                    "callsite_lines",
                ],
                "properties": {
                    "caller_index_name": {"type": "string"},
                    "callsite_lines": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                    "call_type": {
                        "type": "array",
                        "items": {"enum": ["direct", "indirect"]},
                        "minItems": 1,
                        "uniqueItems": True,
                    },
                },
            },
        },
        "project_callees": {
            "type": "array",
            "description": "Program-owned project call edges with canonical snapshot summaries.",
            "items": {
                "type": "object",
                "required": [
                    "callee_index_name",
                    "callee_signature",
                    "is_static",
                    "direct_callsite_lines",
                    "indirect_callsites",
                    "callee_summary",
                ],
                "properties": {
                    "callee_index_name": {"type": "string"},
                    "callee_signature": {"type": "string"},
                    "direct_callsite_lines": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                    "indirect_callsites": {
                        "type": "array",
                        "items": {"type": "object"},
                    },
                    "is_static": {"type": "boolean"},
                    "callee_summary": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        "external_callees": {
            "type": "array",
            "description": "Program-extracted external call edges with compiler-verified signatures.",
            "items": {
                "type": "object",
                "required": [
                    "callee_name",
                    "callee_signature",
                    "direct_callsite_lines",
                    "indirect_callsites",
                ],
                "properties": {
                    "callee_name": {"type": "string"},
                    "callee_signature": {"type": "string"},
                    "direct_callsite_lines": {"type": "array", "items": {"type": "integer"}},
                    "indirect_callsites": {"type": "array", "items": {"type": "object"}},
                },
                "additionalProperties": False,
            },
        },
        "unresolved_callees": {
            "type": "array",
            "description": "Named call targets without a resolved project identity or verified external signature.",
            "items": {
                "type": "object",
                "required": ["callee_name", "direct_callsite_lines", "indirect_callsites"],
                "properties": {
                    "callee_name": {"type": "string"},
                    "direct_callsite_lines": {"type": "array", "items": {"type": "integer"}},
                    "indirect_callsites": {"type": "array", "items": {"type": "object"}},
                },
                "additionalProperties": False,
            },
        },
        "project_callees_truncation": {
            "type": "object",
            "required": ["truncated", "returned", "total"],
            "properties": {
                "truncated": {"const": True},
                "returned": {"type": "integer"},
                "total": {"type": "integer"},
            },
        },
        "external_callees_truncation": {
            "type": "object",
            "required": ["truncated", "returned", "total"],
            "properties": {
                "truncated": {"const": True},
                "returned": {"type": "integer"},
                "total": {"type": "integer"},
            },
        },
        "unresolved_callees_truncation": {
            "type": "object",
            "required": ["truncated", "returned", "total"],
            "properties": {
                "truncated": {"const": True},
                "returned": {"type": "integer"},
                "total": {"type": "integer"},
            },
        },
        "suspicious_points": {
            "type": "array",
            "description": "Audit-relevant suspicious points for later validation. Use an empty array when no suspicious point is present.",
            "items": {
                "type": "object",
                "required": [
                    "category",
                    "lines",
                    "description"
                ],
                "properties": {
                    "category": {"enum": SUSPICIOUS_POINT_CATEGORY_ENUM},
                    "lines": {"type": "string"},
                    "description": {"type": "string"}
                },
            },
        },
    },
}


def _build_java_method_snapshot_schema() -> Dict[str, Any]:
    schema = deepcopy(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    required = list(schema.get("required") or [])
    for field in (
        "language",
        "class_context",
        "annotations",
        "framework_entry",
        "security_checks",
        "sinks",
    ):
        if field not in required:
            required.append(field)
    schema["required"] = required
    properties = schema.setdefault("properties", {})
    properties.update(
        {
            "language": {"const": "java"},
            "class_context": {
                "type": "object",
                "properties": {
                    "package": {"type": "string"},
                    "class_name": {"type": "string"},
                    "extends": {"type": "array", "items": {"type": "string"}},
                    "implements": {"type": "array", "items": {"type": "string"}},
                },
            },
            "annotations": {"type": "array", "items": {"type": "object"}},
            "framework_entry": {
                "type": "object",
                "properties": {
                    "is_entry": {"type": "boolean"},
                    "frameworks": {"type": "array", "items": {"type": "string"}},
                    "routes": {"type": "array", "items": {"type": "string"}},
                },
            },
            "security_checks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string"},
                        "location": {"type": "string"},
                        "description": {"type": "string"},
                    },
                },
            },
            "sinks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string"},
                        "location": {"type": "string"},
                        "expression": {"type": "string"},
                    },
                },
            },
        }
    )
    return schema


DEFAULT_JAVA_METHOD_SNAPSHOT_SCHEMA: Dict[str, Any] = _build_java_method_snapshot_schema()


def snapshot_schema_for_language(language: object) -> Dict[str, Any]:
    text = str(language or "").strip().lower().replace("-", "_")
    if text in {"java", "javasrc", "java_src"}:
        return DEFAULT_JAVA_METHOD_SNAPSHOT_SCHEMA
    return DEFAULT_FUNCTION_SNAPSHOT_SCHEMA


def llm_function_snapshot_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Return the semantic-only schema exposed to the LLM finalizer."""

    result = deepcopy(schema)
    generated = set(LLM_EXCLUDED_SNAPSHOT_FIELDS)
    required = result.get("required")
    if isinstance(required, list):
        result["required"] = [field for field in required if field not in generated]
    properties = result.get("properties")
    if isinstance(properties, dict):
        for field in generated:
            properties.pop(field, None)
    return result

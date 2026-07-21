"""Default semantic snapshot schema used by the semantic modeler."""

from __future__ import annotations

from typing import Any, Dict

FUNCTION_ROLE_ENUM = [
    "entrypoint",
    "parser",
    "validator",
    "dispatcher",
    "allocator",
    "deallocator",
    "resource_acquirer",
    "resource_releaser",
    "initializer",
    "finalizer",
    "state_mutator",
    "state_observer",
    "synchronization",
    "io_boundary",
    "wrapper",
    "callback",
    "error_handler",
    "utility",
    "unknown",
]

DEFAULT_FUNCTION_SNAPSHOT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": [
        "type",
        "func_name",
        "location",
        "summary",
        "role",
        "inputs",
        "outputs",
        "memory",
        "resources",
        "error_paths",
        "concurrency",
        "callees",
        "key_semantics",
        "suspicious_points",
    ],
    "properties": {
        "type": {"const": "function_snapshot"},
        "func_name": {"type": "string"},
        "location": {"type": "string", "description": "file:start_line or similar location"},
        "summary": {"type": "string", "description": "Chinese summary of observable behavior"},
        "role": {"type": "string", "description": "Chinese API role and caller-visible contract"},
        "inputs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "meaning", "trust", "nullable", "constraints"],
                "properties": {
                    "name": {"type": "string"},
                    "meaning": {"type": "string"},
                    "trust": {"enum": ["trusted", "untrusted", "mixed", "unknown"]},
                    "nullable": {"enum": ["yes", "no", "unknown"]},
                    "constraints": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "outputs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "name",
                    "meaning",
                    "success_values",
                    "failure_values",
                    "caller_obligation",
                ],
                "properties": {
                    "name": {"type": "string"},
                    "meaning": {"type": "string"},
                    "success_values": {"type": "array", "items": {"type": "string"}},
                    "failure_values": {"type": "array", "items": {"type": "string"}},
                    "caller_obligation": {"type": "string"},
                },
            },
        },
        "memory": {
            "type": "object",
            "required": [
                "allocations",
                "releases",
                "ownership_transfers",
                "aliases",
                "buffer_bounds",
            ],
            "properties": {
                "allocations": {"$ref": "#/$defs/events"},
                "releases": {"$ref": "#/$defs/events"},
                "ownership_transfers": {"$ref": "#/$defs/events"},
                "aliases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["line", "source", "target", "relationship", "lifetime_note"],
                        "properties": {
                            "line": {"type": ["integer", "null"]},
                            "source": {"type": "string"},
                            "target": {"type": "string"},
                            "relationship": {"type": "string"},
                            "lifetime_note": {"type": "string"},
                        },
                    },
                },
                "buffer_bounds": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "line",
                            "buffer",
                            "size_source",
                            "operation",
                            "bounds_relation",
                        ],
                        "properties": {
                            "line": {"type": ["integer", "null"]},
                            "buffer": {"type": "string"},
                            "size_source": {"type": "string"},
                            "operation": {"type": "string"},
                            "bounds_relation": {"type": "string"},
                        },
                    },
                },
            },
        },
        "resources": {
            "type": "object",
            "required": ["events", "final_state_by_exit"],
            "properties": {
                "events": {"$ref": "#/$defs/events"},
                "final_state_by_exit": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["exit", "line", "condition", "resource_states"],
                        "properties": {
                            "exit": {"type": "string"},
                            "line": {"type": ["integer", "null"]},
                            "condition": {"type": "string"},
                            "resource_states": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["resource", "state", "owner", "risk"],
                                    "properties": {
                                        "resource": {"type": "string"},
                                        "state": {
                                            "enum": [
                                                "released",
                                                "transferred",
                                                "retained",
                                                "still_held",
                                                "leaked",
                                                "unknown",
                                            ]
                                        },
                                        "owner": {"type": "string"},
                                        "risk": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "error_paths": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["line", "condition", "exit", "cleanup_actions", "state_consistency"],
                "properties": {
                    "line": {"type": ["integer", "null"]},
                    "condition": {"type": "string"},
                    "exit": {"type": "string"},
                    "cleanup_actions": {"type": "array", "items": {"type": "string"}},
                    "state_consistency": {"type": "string"},
                },
            },
        },
        "concurrency": {
            "type": "object",
            "required": [
                "shared_state_accesses",
                "locks",
                "lock_order_by_path",
                "thread_effects",
                "atomic_or_refcount_protocols",
            ],
            "properties": {
                "shared_state_accesses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["line", "object", "access", "protection", "race_risk"],
                        "properties": {
                            "line": {"type": ["integer", "null"]},
                            "object": {"type": "string"},
                            "access": {"enum": ["read", "write", "read_write", "unknown"]},
                            "protection": {"type": "string"},
                            "race_risk": {"type": "string"},
                        },
                    },
                },
                "locks": {"$ref": "#/$defs/events"},
                "lock_order_by_path": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["path", "order", "released_on_all_exits", "held_at_exit"],
                        "properties": {
                            "path": {"type": "string"},
                            "order": {"type": "array", "items": {"type": "string"}},
                            "released_on_all_exits": {"enum": ["yes", "no", "unknown"]},
                            "held_at_exit": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
                "thread_effects": {"$ref": "#/$defs/events"},
                "atomic_or_refcount_protocols": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["line", "object", "operation", "protocol", "risk"],
                        "properties": {
                            "line": {"type": ["integer", "null"]},
                            "object": {"type": "string"},
                            "operation": {"type": "string"},
                            "protocol": {"type": "string"},
                            "risk": {"type": "string"},
                        },
                    },
                },
            },
        },
        "callees": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "name",
                    "line",
                    "known_semantics",
                    "contract_summary",
                    "risk_relevance",
                ],
                "properties": {
                    "name": {"type": "string"},
                    "line": {"type": ["integer", "null"]},
                    "known_semantics": {
                        "enum": ["snapshot", "external_config", "inferred", "unknown"]
                    },
                    "contract_summary": {"type": "string"},
                    "risk_relevance": {"type": "string"},
                },
            },
        },
        "key_semantics": {"type": "array", "items": {"type": "string"}},
        "suspicious_points": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["skill", "type", "location", "description", "reason", "confidence"],
                "properties": {
                    "skill": {
                        "enum": [
                            "resource_lifecycle",
                            "temporal_memory",
                            "bounds_and_integer",
                            "string_and_format",
                            "null_and_failure",
                            "ownership_contract",
                            "concurrency_lock_order",
                            "shared_state_race",
                            "stack_escape",
                            "unknown",
                        ]
                    },
                    "type": {"type": "string"},
                    "location": {"type": "string"},
                    "description": {"type": "string"},
                    "reason": {"type": "string"},
                    "confidence": {"enum": ["low", "medium", "high"]},
                },
            },
        },
    },
    "$defs": {
        "events": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "line",
                    "kind",
                    "resource",
                    "operation",
                    "owner_before",
                    "owner_after",
                    "condition",
                ],
                "properties": {
                    "line": {"type": ["integer", "null"]},
                    "kind": {
                        "enum": [
                            "memory",
                            "file",
                            "socket",
                            "mmap",
                            "lock",
                            "thread",
                            "refcount",
                            "shared_state",
                            "other",
                        ]
                    },
                    "resource": {"type": "string"},
                    "operation": {"type": "string"},
                    "owner_before": {"type": "string"},
                    "owner_after": {"type": "string"},
                    "condition": {"type": "string"},
                },
            },
        }
    },
}
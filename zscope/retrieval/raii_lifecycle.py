"""Current-build, single pointer scoped guards; no generic C++ ownership model.

Native identities bind the manager/constructor/destructor. The independently
collected current AST checks the bodies. Neither a destructor event nor a
declared ownership annotation authorizes a release by itself.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from .validation_facts import walk_ast
from .lifecycle_analysis import identity, invocation, location, unwrap

RAII_VERSION = "zscope.scoped-guard.v1"


def native_tool_dependencies(context: dict[str, Any]) -> dict[str, str]:
    binary = context.get("tool", {}).get("binary", {})
    if not binary.get("path") or not binary.get("sha256"):
        return {}
    return {binary["path"]: binary["sha256"], **binary.get("shared_libraries", {})}


def bound_native_facts(data: dict[str, Any], native: dict[str, Any], build: str) -> bool:
    from .build_context import context_input_status
    from .indexing_identity import command_identity, digest_json, dependencies_current

    context = native.get("build_context") or {}
    if (
        not build
        or native.get("build_context_id") != build
        or context.get("build_context_id") != build
        or not native.get("complete")
        or context_input_status(context) != "current"
    ):
        return False
    command = command_identity(data["compile_command"], Path(data["source"]).parent)
    compiler = re.search(r"clang version (\S+)", data.get("compiler", {}).get("version", ""))
    # Clang SDK headers may be spelled via distro symlinks in native facts and
    # resolved by the independent depfile reader. Match actual paths + bytes,
    # never a basename or presumed equivalent compiler resource directory.
    dependencies = {str(Path(p).resolve()): h for p, h in data["dependencies"].items()}
    return bool(
        digest_json(command) == context.get("command_id")
        and compiler
        and compiler[1] == context.get("tool", {}).get("capability", {}).get("clang_version")
        and dependencies_current(native_tool_dependencies(context))
        and all(
            dependencies.get(str(Path(p).resolve())) == h
            for p, h in context["dependencies"].items()
        )
    )


def _body(node: dict[str, Any]) -> list[dict[str, Any]] | None:
    bodies = [n for n in node.get("inner", []) if n.get("kind") == "CompoundStmt"]
    return bodies[0].get("inner", []) if len(bodies) == 1 else None


def _plain(node: dict[str, Any]) -> bool:
    return not any(str(n.get("kind", "")).endswith("Attr") for n in walk_ast(node))


def _noexcept(node: dict[str, Any]) -> bool:
    return str(node.get("type", {}).get("qualType", "")).endswith(
        (" noexcept", " noexcept(true)", " throw()")
    )


class ScopedGuards:
    nonthrowing = staticmethod(_noexcept)

    def standard_root(self, node: dict[str, Any], name: str) -> bool:
        callee = unwrap(node.get("inner", [{}])[0]).get("referencedDecl", {})
        declarations = [
            n
            for n in walk_ast(self.analysis.data["ast"])
            if n.get("id") == callee.get("id") and n.get("kind") == "FunctionDecl"
        ]
        return bool(
            len(declarations) == 1
            and declarations[0].get("mangledName") == name
            and not any(
                n.get("kind") == "FunctionDecl"
                and n.get("mangledName") == name
                and _body(n) is not None
                for n in walk_ast(self.analysis.data["ast"])
            )
        )

    def __init__(self, analysis: Any):
        self.analysis = analysis
        self.models: dict[str, dict[str, Any]] = {}
        self.cpp = any(n.get("kind") == "CXXConstructExpr" for n in walk_ast(analysis.function))
        self.gaps: set[str] = set()
        if not self.cpp:
            return
        native = analysis.data.get("raii_native_facts") or {}
        if not bound_native_facts(analysis.data, native, analysis.data.get("build_context_id", "")):
            self.gaps.add("raii_build_or_native_receipt_unbound")
            return
        functions = native.get("functions") or []
        if (
            len(functions) != 1
            or functions[0].get("cxx_lifetime_facts_version") != "zscope.cxx-lifetime-facts.v1"
        ):
            self.gaps.add("raii_native_lifetime_facts_missing")
            return
        definitions = [
            d for e in native.get("events", []) for d in e.get("defs", []) if d.get("construction")
        ]
        for decl in walk_ast(analysis.function):
            if decl.get("kind") != "VarDecl":
                continue
            children = decl.get("inner", [])
            if not children or children[-1].get("kind") != "CXXConstructExpr":
                continue
            rows = [
                d
                for d in definitions
                if d.get("location", {}).get("offset") == decl.get("loc", {}).get("offset")
            ]
            model = self._model(decl, rows[0]) if len(rows) == 1 else None
            if model:
                self.models[str(decl["id"])] = model
            else:
                self.gaps.add("raii_manager_mapping_or_destructor_unverified")
        # Any use of the manager (including member mutation, escape, copying,
        # move, release/reset or an explicit destructor call) is outside v1.
        if any(
            n.get("kind") == "DeclRefExpr" and identity(n) in self.models
            for n in walk_ast(analysis.function)
        ):
            self.gaps.add("raii_manager_used_outside_construction")

    def _release(
        self, node: dict[str, Any], member: str, seen: set[str]
    ) -> tuple[str, list[str]] | None:
        name, args = invocation(node)
        if len(args) != 1:
            return None
        argument = unwrap(args[0])
        if member.startswith("0x"):
            matches = (
                argument.get("kind") == "MemberExpr"
                and argument.get("referencedMemberDecl") == member
                and len(argument.get("inner", [])) == 1
                and argument["inner"][0].get("kind") == "CXXThisExpr"
            )
        else:
            matches = identity(argument) == member.removeprefix("param:")
        if not matches:
            return None
        callee = unwrap(node.get("inner", [{}])[0]).get("referencedDecl", {})
        declarations = [
            n
            for n in walk_ast(self.analysis.data["ast"])
            if n.get("kind") == "FunctionDecl"
            and n.get("id") == callee.get("id")
            and _body(n) is not None
        ]
        if name == "free" and not declarations and self.standard_root(node, name):
            contracts = self.analysis.registry.find_for_call(name, "deallocator")
            if (
                len(contracts) == 1
                and contracts[0].source == "builtin_defaults"
                and contracts[0].effects_trusted
                and contracts[0].carrier.kind == "argument"
                and contracts[0].carrier.argument_index == 0
                and contracts[0].applicability(["p"], "", {"p": {"non_null_identity": "object"}})
                == "applies"
            ):
                return name, []
            return None
        if name in seen or len(seen) >= 8 or len(declarations) != 1:
            return None
        fn = declarations[0]
        params = [n for n in fn.get("inner", []) if n.get("kind") == "ParmVarDecl"]
        body = _body(fn)
        if (
            not _noexcept(fn)
            or not _plain(fn)
            or len(params) != 1
            or body is None
            or len(body) != 1
        ):
            return None
        result = self._release(body[0], "param:" + params[0]["id"], seen | {name})
        return (result[0], [name, *result[1]]) if result else None

    def _model(self, decl: dict[str, Any], native: dict[str, Any]) -> dict[str, Any] | None:
        construct = decl["inner"][-1]
        receipt = native["construction"]
        if (
            not receipt.get("automatic_storage")
            or not receipt.get("complete_object")
            or not _plain(decl)
        ):
            return None
        records = [
            n
            for n in self.analysis.data["ast"].get("inner", [])
            if n.get("kind") == "CXXRecordDecl"
            and n.get("completeDefinition")
            and n.get("name") == construct.get("type", {}).get("qualType")
        ]
        if len(records) != 1:
            return None
        record = records[0]
        if record.get("bases") or record.get("tagUsed") == "union" or not _plain(record):
            return None
        fields = [n for n in record.get("inner", []) if n.get("kind") == "FieldDecl"]
        if (
            len(fields) != 1
            or not str(fields[0].get("type", {}).get("qualType", "")).endswith(" *")
            or fields[0].get("isBitfield")
        ):
            return None
        if "volatile" in fields[0]["type"]["qualType"] or "atomic" in fields[0]["type"]["qualType"]:
            return None
        selected = []
        for kind, key in (
            ("CXXConstructorDecl", "constructor"),
            ("CXXDestructorDecl", "destructor"),
        ):
            target = receipt.get(key) or {}
            rows = [
                n
                for n in record.get("inner", [])
                if n.get("kind") == kind
                and not n.get("isImplicit")
                and n.get("loc", {}).get("offset") == target.get("location", {}).get("offset")
            ]
            if (
                len(rows) != 1
                or not target.get("usr")
                or not target.get("has_definition")
                or not _noexcept(rows[0])
                or rows[0].get("virtual")
                or str(Path(target.get("location", {}).get("file", "")).resolve())
                != self.analysis.data["source"]
            ):
                return None
            selected.append(rows[0])
        ctor, dtor = selected
        params = [n for n in ctor.get("inner", []) if n.get("kind") == "ParmVarDecl"]
        inits = [n for n in ctor.get("inner", []) if n.get("kind") == "CXXCtorInitializer"]
        if (
            len(params) != 1
            or params[0].get("type") != fields[0].get("type")
            or _body(ctor) != []
            or len(inits) != 1
            or inits[0].get("anyInit", {}).get("id") != fields[0]["id"]
            or len(inits[0].get("inner", [])) != 1
            or identity(inits[0]["inner"][0]) != params[0]["id"]
            or len(construct.get("inner", [])) != 1
        ):
            return None
        body = _body(dtor)
        if body is None or len(body) != 1:
            return None
        action = body[0]
        if action.get("kind") == "IfStmt":
            parts = action.get("inner", [])
            if len(parts) != 2 or action.get("hasInit"):
                return None
            condition = parts[0]
            if condition.get("castKind") == "PointerToBoolean":
                condition = condition.get("inner", [{}])[0]
            condition = unwrap(condition)
            if (
                condition.get("kind") != "MemberExpr"
                or condition.get("referencedMemberDecl") != fields[0]["id"]
                or condition.get("inner", [{}])[0].get("kind") != "CXXThisExpr"
            ):
                return None
            action = parts[1]
        if action.get("kind") == "CompoundStmt" and len(action.get("inner", [])) == 1:
            action = action["inner"][0]
        effect = self._release(action, fields[0]["id"], set())
        if not effect:
            return None
        return {
            "manager_usr": native["usr"],
            "constructor_usr": receipt["constructor"]["usr"],
            "destructor_usr": receipt["destructor"]["usr"],
            "member": fields[0]["name"],
            "release_api": effect[0],
            "release_wrappers": effect[1],
            "argument": construct["inner"][0],
            "line": location(decl, self.analysis.source)[0],
        }

    def construct(self, decl: dict[str, Any], state: Any) -> bool:
        model = self.models.get(str(decl.get("id")))
        if not model:
            return False
        arg = model["argument"]
        uid = self.analysis._resource(arg, state)
        empty = unwrap(arg).get("kind") in {"CXXNullPtrLiteralExpr", "GNUNullExpr"} or (
            unwrap(arg).get("kind") == "IntegerLiteral" and unwrap(arg).get("value") == "0"
        )
        if not uid and not empty:
            state.complete = False
            self.analysis.gaps.add("raii_resource_identity_unresolved")
        if uid and (
            self.analysis.acquisitions[uid]["api"] not in {"malloc", "calloc"}
            or state.resources[uid] not in {"held", "not_acquired"}
        ):
            state.complete = False
            self.analysis.gaps.add("raii_resource_state_or_family_unclosed")
        state.guards[str(decl["id"])] = (uid, model)
        return True

    def cleanup(self, managers: list[str], state: Any) -> None:
        for manager in reversed(managers):
            entry = state.guards.pop(manager, None)
            if entry is None:
                continue
            uid, model = entry
            if uid and state.complete:
                if state.resources.get(uid) == "held" and self.analysis.registry.allows(
                    self.analysis.acquisitions[uid]["api"], model["release_api"]
                ):
                    state.resources[uid] = "released"
                elif state.resources.get(uid) != "not_acquired":
                    state.complete = False
                    self.analysis.gaps.add("raii_duplicate_release_or_owner_escape")
            self.analysis.events.append(
                {
                    "kind": "scoped_guard_cleanup",
                    "schema": RAII_VERSION,
                    "acquisition_id": uid,
                    "manager_usr": model["manager_usr"],
                    "destructor_usr": model["destructor_usr"],
                    "member": model["member"],
                    "release_api": model["release_api"],
                    "empty": not uid,
                    "exit_kind": (
                        "caught_throw_unwind" if state.exceptional else "normal_scope_exit"
                    ),
                    "build_context_id": self.analysis.data.get("build_context_id"),
                    "proof_authority": False,
                }
            )

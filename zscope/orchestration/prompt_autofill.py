"""Autofill batch-entry custom prompts from Z-SCOPE code-index evidence."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..config.config import PromptAutofillConfig
from ..config.function_entry import FunctionEntry
from ..retrieval.code_index import CodeIndex

logger = logging.getLogger(__name__)

ALLOC_NAME_RE = re.compile(r"(Create|Add|Alloc|Apply|Register|Bind|Connect|Join)", re.I)
RELEASE_NAME_RE = re.compile(r"(Delete|Remove|Free|Release|Close|Destroy|Leave)", re.I)
DISPATCH_NAME_RE = re.compile(r"(MsgProc|Dispatch|Route)", re.I)
FAULT_NAME_RE = re.compile(r"(Fault|Error|Cleanup|Abort)", re.I)
QUERY_NAME_RE = re.compile(r"(Get|Query|Info|Stat)", re.I)
INIT_NAME_RE = re.compile(r"(Init|Finit|ResInit|ResFinit)", re.I)

ALLOC_CALL_RE = re.compile(
    r"\b(DDM_ALLOC|DDM_BitMapGetFree|DDM_BitMapSet|malloc|calloc|realloc|mmap|open|socket)\s*\(",
    re.I,
)
RELEASE_CALL_RE = re.compile(
    r"\b(DDM_FREE|DDM_BitMapUnSet|free|munmap|close|MESH_CLOSE_FD|DDM_Close_s)\s*\(",
    re.I,
)
GLOBAL_DS_RE = re.compile(
    r"\b(g_st\w+|LIST|List|Hash|hash|BitMap|Bitmap|DDM_List|ADD|DEL|REMOVE)\b"
)
LOCK_RE = re.compile(
    r"(mutex|rwlock|spinlock|pthread_mutex|pthread_rwlock|\bLOCK\b|\bUNLOCK\b)", re.I
)
ERROR_PATH_RE = re.compile(r"\b(return|goto|ERROR|FAIL|ERR|ENOMEM|EINVAL)\b")
MESSAGE_TYPE_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]+_(?:MSG|REQUEST|NOTIFY|APPLY|FREE|CLOSE)[A-Z0-9_]*)\b"
)
LITERAL_PARAM_CALL_RE = re.compile(
    r"\b(?P<callee>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^;{}]*\b(?:VOS_TRUE|VOS_FALSE|TRUE|FALSE|0|1)\b[^;{}]*)\)\s*;",
    re.S,
)
ROLE_FIELD_RE = re.compile(
    r"\b(uc[A-Za-z0-9_]*(?:Type|Role|Mode)|en[A-Za-z0-9_]*(?:Type|Role|Mode))\b"
)


@dataclass
class PromptAutofillResult:
    """Summary of prompt autofill activity."""

    updated: List[str] = field(default_factory=list)
    skipped_existing: List[str] = field(default_factory=list)
    unmatched: List[str] = field(default_factory=list)
    missing_impl: List[str] = field(default_factory=list)
    write_back_path: Optional[Path] = None


@dataclass
class FunctionEvidence:
    """Signals extracted from one function body."""

    name: str
    code: str
    callees: List[str]
    file_path: str = ""
    message_type: str = ""
    allocation_calls: List[str] = field(default_factory=list)
    release_calls: List[str] = field(default_factory=list)
    global_structures: List[str] = field(default_factory=list)
    role_fields: List[str] = field(default_factory=list)
    literal_param_calls: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def has_locks(self) -> bool:
        return bool(LOCK_RE.search(self.code))

    @property
    def has_error_paths(self) -> bool:
        return bool(ERROR_PATH_RE.search(self.code))

    @property
    def has_global_ds(self) -> bool:
        return bool(self.global_structures)

    @property
    def has_allocation(self) -> bool:
        return bool(self.allocation_calls or ALLOC_NAME_RE.search(self.name))

    @property
    def has_release(self) -> bool:
        return bool(self.release_calls or RELEASE_NAME_RE.search(self.name))

    @property
    def has_conditional_literal_release(self) -> bool:
        release_names = ("close", "free", "release", "remove", "destroy", "delete")
        return any(
            any(part in callee.lower() for part in release_names)
            for callee, _ in self.literal_param_calls
        )


class PromptAutofillExecutor:
    """Generate and optionally persist custom_prompt for batch entries."""

    def __init__(
        self,
        code_index: CodeIndex,
        config: Optional[PromptAutofillConfig] = None,
    ) -> None:
        self.code_index = code_index
        self.config = config or PromptAutofillConfig()

    def autofill(
        self,
        entries: List[FunctionEntry],
        *,
        source_json_path: Optional[Path] = None,
    ) -> PromptAutofillResult:
        result = PromptAutofillResult()
        if not self.config.enabled:
            return result

        existing_prompts = {
            entry.function_name: entry.custom_prompt or ""
            for entry in entries
            if entry.custom_prompt
        }
        known_names = [entry.function_name for entry in entries]
        generated_by_key: Dict[Tuple[str, str], str] = {}

        for entry in entries:
            if self._has_complete_prompt(entry.custom_prompt):
                result.skipped_existing.append(entry.function_name)
                continue

            evidence = self._evidence_for_entry(entry, result)
            if not evidence:
                prompt = self._prompt_from_name_only(
                    entry.function_name, existing_prompts, known_names
                )
            else:
                prompt = self._generate_prompt(evidence, existing_prompts, known_names)

            if not prompt:
                result.unmatched.append(entry.function_name)
                continue

            entry.custom_prompt = prompt
            result.updated.append(entry.function_name)
            generated_by_key[self._entry_key(entry)] = prompt

        if source_json_path and self.config.write_back and generated_by_key:
            self._write_back(source_json_path, generated_by_key)
            result.write_back_path = Path(source_json_path)

        return result

    def _has_complete_prompt(self, prompt: Optional[str]) -> bool:
        if not prompt:
            return False
        if self.config.overwrite_existing:
            return False
        return len(prompt.strip()) >= self.config.min_custom_prompt_chars

    def _evidence_for_entry(
        self,
        entry: FunctionEntry,
        result: PromptAutofillResult,
    ) -> Optional[FunctionEvidence]:
        impl = self.code_index.get_function_impl(
            entry.function_name,
            max_lines=self.config.max_function_lines,
            warn_missing=False,
        )
        if not impl:
            result.missing_impl.append(entry.function_name)
            return None

        code = str(impl.get("code") or "")
        callees = self._callee_names(entry.function_name)
        return FunctionEvidence(
            name=entry.function_name,
            code=code,
            callees=callees,
            file_path=str(impl.get("file") or entry.file_path or ""),
            message_type=self._first_match(MESSAGE_TYPE_RE, code),
            allocation_calls=self._unique(ALLOC_CALL_RE.findall(code)),
            release_calls=self._unique(RELEASE_CALL_RE.findall(code)),
            global_structures=self._unique(GLOBAL_DS_RE.findall(code)),
            role_fields=self._unique(ROLE_FIELD_RE.findall(code)),
            literal_param_calls=self._literal_param_calls(code),
        )

    def _callee_names(self, function_name: str) -> List[str]:
        try:
            records = self.code_index.get_callees(function_name, limit=self.config.max_callees)
        except Exception as exc:
            logger.debug("Callee lookup failed for %s: %s", function_name, exc)
            return []
        names = []
        for record in records:
            if isinstance(record, str):
                names.append(record)
            elif isinstance(record, dict):
                value = (
                    record.get("name")
                    or record.get("callee")
                    or record.get("to")
                    or record.get("function")
                )
                if value:
                    names.append(str(value))
        return self._unique(names)

    def _generate_prompt(
        self,
        evidence: FunctionEvidence,
        existing_prompts: Dict[str, str],
        known_names: Sequence[str],
    ) -> str:
        category = self._category(evidence)
        pair = self._paired_function(evidence.name, existing_prompts, known_names, category)

        if category == "dispatch":
            return self._dispatch_prompt(evidence)
        if category == "fault":
            return self._fault_prompt(evidence, pair)
        if category == "init_destroy":
            return self._init_destroy_prompt(evidence)
        if category == "query":
            return self._query_prompt(evidence)
        if category == "release":
            return self._release_prompt(evidence, pair)
        if category == "allocation":
            return self._allocation_prompt(evidence, pair)

        if evidence.has_conditional_literal_release:
            return self._conditional_param_prompt(evidence)
        return self._generic_prompt(evidence)

    def _category(self, evidence: FunctionEvidence) -> str:
        name = evidence.name
        has_dispatch_body = (
            "switch" in evidence.code
            or "case " in evidence.code
            or "astMsgProcApi" in evidence.code
        )
        if DISPATCH_NAME_RE.search(name) and has_dispatch_body:
            return "dispatch"
        if FAULT_NAME_RE.search(name):
            return "fault"
        if INIT_NAME_RE.search(name):
            return "init_destroy"
        if evidence.has_conditional_literal_release:
            return "release"
        if ALLOC_NAME_RE.search(name):
            return "allocation"
        if RELEASE_NAME_RE.search(name):
            return "release"
        if evidence.allocation_calls:
            return "allocation"
        if evidence.release_calls:
            return "release"
        if QUERY_NAME_RE.search(name):
            return "query"
        if DISPATCH_NAME_RE.search(name):
            return "dispatch"
        return "generic"

    def _dispatch_prompt(self, evidence: FunctionEvidence) -> str:
        module = self._module_name(evidence)
        if "astMsgProcApi" in evidence.code:
            dispatch = "采用表驱动分发(函数指针数组astMsgProcApi)"
            first_check = "数组中是否有消息类型重复"
        elif "switch" in evidence.code:
            dispatch = (
                f"根据消息类型({evidence.message_type or '如XXX_MSG等'})将消息路由到对应的处理函数"
            )
            first_check = "switch/case分支是否覆盖了所有消息类型、是否有未处理的case"
        else:
            dispatch = "负责将请求路由到对应handler"
            first_check = "分发条件是否覆盖所有有效消息类型"

        release_call = self._first_matching_name(
            evidence.release_calls, ("MsgFree", "DlinkMsgFree", "Free")
        )
        release_check = (
            f"每个分支处理完毕后消息缓冲区是否被正确释放({release_call})"
            if release_call
            else "每个分支处理完毕后消息缓冲区或临时资源是否被正确释放"
        )
        return (
            f"这是{module}层的核心消息分发函数，{dispatch}。请分析：(1){first_check} "
            f"(2)未匹配的消息是否都走到默认处理 (3){release_check}"
        )

    def _allocation_prompt(
        self,
        evidence: FunctionEvidence,
        pair: str,
    ) -> str:
        msg = f"处理{evidence.message_type}。" if evidence.message_type else ""
        resource = self._resource_name(evidence)
        alloc = self._call_summary(
            evidence.allocation_calls, fallback="DDM_ALLOC/位图/系统资源分配"
        )
        ds = self._global_ds_summary(evidence)
        pair_text = (
            f"，在{pair}(正常释放/故障清理)中被释放"
            if pair
            else "，在配对释放handler或故障清理路径中被释放"
        )

        checks = []
        if evidence.has_error_paths:
            checks.append("错误路径上的资源回滚是否完整")
        if (
            "DDM_BitMapGetFree" in evidence.allocation_calls
            or "DDM_BitMapSet" in evidence.allocation_calls
        ):
            checks.append("位图分配失败、耗尽以及后续失败时是否正确回滚位图")
        if evidence.has_global_ds:
            checks.append(
                f"{resource}节点挂载到{ds}后的条件覆盖是否完整，是否存在某种条件下永远不会被摘除"
            )
        if evidence.has_locks:
            checks.append("锁保护范围和多把锁加锁顺序是否正确")
        checks.append("释放职责是否确实由配对handler承担，避免把跨handler生命周期误报为泄漏")
        return (
            f"{msg}分配{resource}资源(通过{alloc})，挂载在{ds}上{pair_text}。"
            f"这是跨handler生命周期，{resource}不在本函数释放，请不要报告为泄漏。"
            f"请重点关注：{self._numbered(checks)}"
        )

    def _release_prompt(
        self,
        evidence: FunctionEvidence,
        pair: str,
    ) -> str:
        if evidence.has_conditional_literal_release and evidence.role_fields:
            return self._conditional_param_prompt(evidence)

        msg = f"处理{evidence.message_type}。" if evidence.message_type else ""
        resource = self._resource_name(evidence)
        release = self._call_summary(evidence.release_calls, fallback="DDM_FREE/close/位图释放")
        ds = self._global_ds_summary(evidence)
        pair_text = f"这是{pair}的配对释放handler。" if pair else "这是配对分配handler的释放端。"
        checks = [
            f"{resource}不存在或已释放时的处理",
            "释放后是否有悬挂指针或重复释放风险",
        ]
        if evidence.has_global_ds:
            checks.insert(1, f"从{ds}移除时链表/hash/位图操作是否正确")
        if "DDM_BitMapUnSet" in evidence.release_calls:
            checks.append("位图槽位释放(DDM_BitMapUnSet)与DDM_FREE的顺序是否安全")
        if evidence.has_locks:
            checks.append("释放流程是否完整处于正确锁保护下")
        return (
            f"{msg}释放{resource}资源({release})，从{ds}移除。{pair_text}"
            f"请重点关注：{self._numbered(checks)}"
        )

    def _fault_prompt(self, evidence: FunctionEvidence, pair: str) -> str:
        resource = self._resource_name(evidence)
        ds = self._global_ds_summary(evidence)
        normal = pair or "正常释放函数"
        checks = [
            f"遍历{ds}时是否遗漏了某种资源类型",
            f"{resource}批量释放时关联计数、位图或嵌套节点是否同步清理",
        ]
        if evidence.has_locks:
            checks.append("批量释放过程中锁保护是否充分")
        checks.append("是否存在只释放外层资源但遗漏成员/子节点的情况")
        return (
            f"这是故障安全网函数，当连接断开、异常或清理触发时被调用。"
            f"它遍历全局{ds}中相关的{resource}并批量释放。"
            f"这是所有资源生命周期的最终兜底释放路径，正常情况下资源应已在{normal}中释放。"
            f"请重点关注：{self._numbered(checks)}"
        )

    def _query_prompt(self, evidence: FunctionEvidence) -> str:
        msg = f"处理{evidence.message_type}。" if evidence.message_type else ""
        checks = ["响应消息构造是否正确"]
        if evidence.allocation_calls:
            checks.append("响应或临时内存分配失败时的处理")
        else:
            checks.append("只读路径是否错误修改了全局状态")
        return f"{msg}此函数只读取信息并发送响应，不涉及跨handler资源管理。请检查：{self._numbered(checks)}"

    def _init_destroy_prompt(self, evidence: FunctionEvidence) -> str:
        module = self._module_name(evidence)
        if "Finit" in evidence.name or "Destroy" in evidence.name:
            checks = [
                "pthread_mutex_destroy前是否确保无线程持有锁",
                "hash表/链表/位图遍历释放是否遗漏资源",
                "残留资源的释放顺序是否安全",
            ]
            return f"{module}资源销毁函数。销毁全局mutex、hash表等基础设施。请检查：{self._numbered(checks)}"
        checks = ["pthread_mutex_init失败时的处理", "hash表/链表/位图初始化是否完整"]
        if evidence.has_error_paths:
            checks.append("部分初始化成功后后续失败时是否回滚已初始化资源")
        return f"{module}资源初始化函数。初始化全局mutex、hash表等基础设施。请检查：{self._numbered(checks)}"

    def _conditional_param_prompt(self, evidence: FunctionEvidence) -> str:
        callee, args = (
            evidence.literal_param_calls[0] if evidence.literal_param_calls else ("释放函数", "")
        )
        literal = self._first_literal(args)
        role_field = evidence.role_fields[0] if evidence.role_fields else "角色/类型字段"
        return (
            f"释放资源时调用{callee}并传入条件参数{literal or '字面量'}。该类释放函数可能根据条件参数选择不同资源摘除路径，"
            f"而本函数中存在{role_field}等角色标识字段，必须验证角色到条件参数的映射是否正确。"
            f"请重点关注：(1){callee}的条件参数是否根据{role_field}区分不同角色 "
            f"(2)如果硬编码为{literal or '固定值'}，某些角色关闭时可能走错摘除路径，导致对应节点永远不被摘除而泄漏 "
            f"(3)请反向验证创建/加入路径中{role_field}的赋值与所有关闭路径传参是否一致"
        )

    def _generic_prompt(self, evidence: FunctionEvidence) -> str:
        checks = ["错误路径是否保持状态一致"]
        if evidence.has_global_ds:
            checks.append("全局数据结构操作的条件覆盖是否完整")
        if evidence.has_locks:
            checks.append("锁保护范围是否覆盖所有共享状态访问")
        if evidence.has_error_paths:
            checks.append("提前返回路径是否遗漏清理或响应")
        return f"请结合此函数的实际职责进行审计。请重点关注：{self._numbered(checks)}"

    def _prompt_from_name_only(
        self,
        function_name: str,
        existing_prompts: Dict[str, str],
        known_names: Sequence[str],
    ) -> str:
        pair = self._paired_function(function_name, existing_prompts, known_names, "generic")
        if RELEASE_NAME_RE.search(function_name) and pair:
            return f"这是{pair}的配对释放handler。请重点关注：(1)资源不存在时的处理 (2)释放后是否有悬挂指针 (3)重复释放防护"
        if ALLOC_NAME_RE.search(function_name):
            tail = f"，在{pair}中被释放" if pair else ""
            return f"此函数可能分配跨handler生命周期资源{tail}，请不要仅因本函数未释放就报告为泄漏。请重点关注：(1)错误路径回滚 (2)配对释放路径是否完整 (3)锁保护范围"
        return ""

    def _paired_function(
        self,
        function_name: str,
        existing_prompts: Dict[str, str],
        known_names: Sequence[str],
        category: str,
    ) -> str:
        for other_name, prompt in existing_prompts.items():
            if other_name == function_name:
                continue
            if function_name in prompt:
                return other_name
            if other_name in prompt and category in {"allocation", "release", "fault", "generic"}:
                return other_name

        candidates = self._name_pair_candidates(function_name, category)
        known_lower = {name.lower(): name for name in known_names}
        for candidate in candidates:
            found = known_lower.get(candidate.lower())
            if found and found != function_name:
                return found
        return ""

    @staticmethod
    def _name_pair_candidates(function_name: str, category: str) -> List[str]:
        pairs = (
            ("Apply", "Release"),
            ("Alloc", "Free"),
            ("Create", "Destroy"),
            ("Add", "Del"),
            ("Add", "Delete"),
            ("Register", "Unregister"),
            ("Bind", "Close"),
            ("Connect", "Close"),
            ("Join", "Leave"),
        )
        candidates = []
        for left, right in pairs:
            if left in function_name:
                candidates.append(function_name.replace(left, right))
            if right in function_name:
                candidates.append(function_name.replace(right, left))
        if category == "fault":
            candidates.extend(name for name in candidates if RELEASE_NAME_RE.search(name))
        return candidates

    @staticmethod
    def _literal_param_calls(code: str) -> List[Tuple[str, str]]:
        calls = []
        for match in LITERAL_PARAM_CALL_RE.finditer(code):
            callee = match.group("callee")
            args = " ".join(match.group("args").split())
            if any(
                word in callee.lower()
                for word in ("close", "free", "release", "remove", "destroy", "delete")
            ):
                calls.append((callee, args))
        return calls[:3]

    @staticmethod
    def _first_literal(args: str) -> str:
        match = re.search(r"\b(VOS_TRUE|VOS_FALSE|TRUE|FALSE|0|1)\b", args)
        return match.group(1) if match else ""

    @staticmethod
    def _module_name(evidence: FunctionEvidence) -> str:
        if evidence.file_path:
            stem = Path(evidence.file_path).stem
            if stem:
                return stem
        match = re.match(r"([a-z]+(?:Server|Client|Mcm|Mesh|Xmesh)?)", evidence.name)
        return match.group(1) if match else "当前模块"

    @staticmethod
    def _resource_name(evidence: FunctionEvidence) -> str:
        lower = evidence.name.lower()
        if "port" in lower:
            return "端口号"
        if "mcm" in lower or "member" in lower:
            return "MCM/成员节点"
        if "conn" in lower:
            return "连接"
        if "bind" in lower:
            return "bind_info"
        if "listen" in lower:
            return "listen_info"
        if "shm" in lower:
            return "共享内存"
        if "fd" in lower or "socket" in lower:
            return "fd/socket"
        if evidence.allocation_calls or evidence.release_calls:
            return "相关"
        return "函数相关"

    @staticmethod
    def _global_ds_summary(evidence: FunctionEvidence) -> str:
        if not evidence.global_structures:
            return "全局数据结构"
        return "/".join(evidence.global_structures[:3])

    @staticmethod
    def _call_summary(calls: Sequence[str], fallback: str) -> str:
        unique = PromptAutofillExecutor._unique(calls)
        return "/".join(unique[:4]) if unique else fallback

    @staticmethod
    def _first_matching_name(names: Sequence[str], needles: Sequence[str]) -> str:
        for name in names:
            if any(needle in name for needle in needles):
                return name
        return ""

    @staticmethod
    def _first_match(pattern: re.Pattern[str], text: str) -> str:
        match = pattern.search(text)
        return match.group(1) if match else ""

    @staticmethod
    def _numbered(items: Iterable[str]) -> str:
        unique = [item for item in dict.fromkeys(items) if item]
        return " ".join(f"({idx}){item}" for idx, item in enumerate(unique[:5], 1))

    @staticmethod
    def _unique(items: Iterable[str]) -> List[str]:
        result = []
        seen = set()
        for item in items:
            text = str(item).strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(text)
        return result

    @staticmethod
    def _entry_key(entry: FunctionEntry) -> Tuple[str, str]:
        return (entry.function_name, entry.file_path or "")

    def _write_back(
        self,
        source_json_path: Path,
        generated_by_key: Dict[Tuple[str, str], str],
    ) -> None:
        path = Path(source_json_path)
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
        functions = data.get("functions")
        if not isinstance(functions, list):
            raise ValueError(f"Cannot write prompt autofill: 'functions' is not an array in {path}")

        changed = False
        for item in functions:
            if not isinstance(item, dict):
                continue
            function_name = item.get("function_name")
            if not function_name:
                continue
            file_path = item.get("file_path") or ""
            prompt = generated_by_key.get((function_name, file_path))
            if prompt is None:
                prompt = generated_by_key.get((function_name, ""))
            if prompt is None:
                continue
            if self._has_complete_prompt(item.get("custom_prompt")):
                continue
            if item.get("custom_prompt") == prompt:
                continue
            item["custom_prompt"] = prompt
            changed = True

        if changed:
            indent = self._detect_json_indent(raw_text)
            path.write_text(
                json.dumps(data, ensure_ascii=False, indent=indent) + "\n",
                encoding="utf-8",
            )

    @staticmethod
    def _detect_json_indent(raw_text: str) -> int:
        match = re.search(r'\n( +)"functions"\s*:', raw_text)
        if match:
            return max(2, len(match.group(1)))
        match = re.search(r'\n( +)\{[^\n]*"function_name"', raw_text)
        if match:
            return max(2, len(match.group(1)))
        return 2

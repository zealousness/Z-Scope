"""Entry-point discovery and exposure classification for C projects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..config.function_entry import FunctionEntry
from ..retrieval.code_index import CodeIndex


API_PROMPT = "Public API declared in a header file. Audit caller-controlled arguments and API contract misuse."
COMM_PROMPT = "Communication or IPC entry. Audit data received from peers, framing, length checks, and trust boundaries."
THREAD_PROMPT = "Thread entry or thread creator. Audit stack lifetime, shared state, lock ordering, and handoff ownership."
INPUT_PROMPT = "User-controlled input entry. Audit external data parsing, size conversion, and resource cleanup."


@dataclass
class EntryCandidate:
    function_name: str
    exposure: str
    reasons: List[str] = field(default_factory=list)
    file_path: str = ""
    line: int = 0
    custom_prompt: str = ""
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "exposure": self.exposure,
            "reasons": self.reasons,
            "file_path": self.file_path,
            "line": self.line,
            "custom_prompt": self.custom_prompt,
            "confidence": self.confidence,
        }

    def to_function_entry(self) -> FunctionEntry:
        return FunctionEntry(
            function_name=self.function_name,
            custom_prompt=self.custom_prompt,
            file_path=self.file_path or None,
        )


@dataclass
class EntryDiscoveryResult:
    exposure_kind: str
    candidates: List[EntryCandidate]
    summary: Dict[str, int]
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exposure_kind": self.exposure_kind,
            "summary": self.summary,
            "notes": self.notes,
            "candidates": [c.to_dict() for c in self.candidates],
        }

    def to_function_entries(self) -> List[FunctionEntry]:
        return [candidate.to_function_entry() for candidate in self.candidates]


class EntryDiscovery:
    """Classifies project exposure and selects likely scan entry functions."""

    DEFAULT_COMMUNICATION_CALLS = (
        "recv",
        "recvfrom",
        "recvmsg",
        "send",
        "sendto",
        "sendmsg",
        "read",
        "readv",
        "write",
        "writev",
        "socket",
        "accept",
        "accept4",
        "connect",
        "bind",
        "listen",
        "select",
        "poll",
        "epoll_wait",
        "mq_receive",
        "mq_send",
    )
    DEFAULT_SHARED_MEMORY_CALLS = (
        "shm_open",
        "shmat",
        "shmget",
        "mmap",
        "munmap",
        "MapViewOfFile",
        "CreateFileMapping",
    )
    DEFAULT_THREAD_CALLS = (
        "pthread_create",
        "thrd_create",
        "CreateThread",
        "_beginthread",
        "_beginthreadex",
        "clone",
    )
    DEFAULT_INPUT_CALLS = (
        "scanf",
        "fscanf",
        "sscanf",
        "gets",
        "fgets",
        "getline",
        "getdelim",
        "getchar",
        "getenv",
        "getopt",
        "ioctl",
        "fread",
        "fopen",
        "open",
        "argv",
    )

    def __init__(
        self,
        code_index: CodeIndex,
        max_functions: int = 10000,
        header_files: Optional[List[str]] = None,
        communication_calls: Optional[Sequence[str]] = None,
        shared_memory_calls: Optional[Sequence[str]] = None,
        thread_calls: Optional[Sequence[str]] = None,
        input_calls: Optional[Sequence[str]] = None,
    ):
        self.code_index = code_index
        self.max_functions = max_functions
        self.header_files = header_files
        self.communication_calls = tuple(communication_calls or self.DEFAULT_COMMUNICATION_CALLS)
        self.shared_memory_calls = tuple(shared_memory_calls or self.DEFAULT_SHARED_MEMORY_CALLS)
        self.thread_calls = tuple(thread_calls or self.DEFAULT_THREAD_CALLS)
        self.input_calls = tuple(input_calls or self.DEFAULT_INPUT_CALLS)

    def discover(self, max_candidates: int = 200) -> EntryDiscoveryResult:
        header_candidates = self._discover_header_api()
        body_candidates = self._discover_body_entries()

        merged = self._merge_candidates(header_candidates + body_candidates)
        merged.sort(key=lambda c: (-c.confidence, c.function_name))
        selected = merged[:max_candidates]

        summary: Dict[str, int] = {}
        for candidate in selected:
            summary[candidate.exposure] = summary.get(candidate.exposure, 0) + 1

        has_api = any("api" in c.exposure for c in selected)
        has_comm = any("communication" in c.exposure or "thread" in c.exposure for c in selected)
        has_other = any(c.exposure == "other_user_input" for c in selected)
        if has_api and has_comm:
            exposure_kind = "mixed_api_and_communication"
        elif has_api:
            exposure_kind = "api_only"
        elif has_comm:
            exposure_kind = "communication_or_thread_only"
        elif has_other:
            exposure_kind = "other_user_input"
        else:
            exposure_kind = "configured_or_internal_only"

        notes = []
        if not selected:
            notes.append("No header API, communication, thread, or other user-input entry candidates were found.")
        if len(merged) > len(selected):
            notes.append(f"Truncated {len(merged)} candidates to {len(selected)} by confidence.")

        return EntryDiscoveryResult(exposure_kind=exposure_kind, candidates=selected, summary=summary, notes=notes)

    def _discover_header_api(self) -> List[EntryCandidate]:
        candidates: List[EntryCandidate] = []
        for item in self.code_index.get_header_declared_functions(self.header_files):
            name = item.get("name")
            if not name:
                continue
            impl = self.code_index.get_function_impl(name)
            if not impl:
                continue
            candidates.append(
                EntryCandidate(
                    function_name=name,
                    exposure="api",
                    reasons=["declared_in_header"],
                    file_path=item.get("filename") or impl.get("file", ""),
                    line=int(item.get("lineNumber") or impl.get("start_line") or 0),
                    custom_prompt=API_PROMPT,
                    confidence=0.9,
                )
            )
        return candidates

    def _discover_body_entries(self) -> List[EntryCandidate]:
        candidates: List[EntryCandidate] = []
        for name in self.code_index.list_functions(limit=self.max_functions):
            impl = self.code_index.get_function_impl(name)
            if not impl:
                continue
            code = impl.get("code") or ""
            reasons: List[str] = []
            exposure_parts: List[str] = []

            comm_hits = self._find_calls(code, self.communication_calls)
            shm_hits = self._find_calls(code, self.shared_memory_calls)
            thread_hits = self._find_calls(code, self.thread_calls)
            input_hits = self._find_calls(code, self.input_calls)

            if comm_hits or shm_hits:
                exposure_parts.append("communication")
                reasons.extend([f"calls:{hit}" for hit in comm_hits])
                reasons.extend([f"shared_memory:{hit}" for hit in shm_hits])
            if thread_hits:
                exposure_parts.append("thread")
                reasons.extend([f"thread:{hit}" for hit in thread_hits])
            if input_hits and not exposure_parts:
                exposure_parts.append("other_user_input")
                reasons.extend([f"input:{hit}" for hit in input_hits])

            if not exposure_parts:
                continue

            exposure = "+".join(dict.fromkeys(exposure_parts))
            prompt_parts = []
            if "communication" in exposure:
                prompt_parts.append(COMM_PROMPT)
            if "thread" in exposure:
                prompt_parts.append(THREAD_PROMPT)
            if exposure == "other_user_input":
                prompt_parts.append(INPUT_PROMPT)

            candidates.append(
                EntryCandidate(
                    function_name=name,
                    exposure=exposure,
                    reasons=sorted(set(reasons)),
                    file_path=impl.get("file", ""),
                    line=int(impl.get("start_line") or 0),
                    custom_prompt=" ".join(prompt_parts),
                    confidence=0.85 if exposure != "other_user_input" else 0.7,
                )
            )
        return candidates

    def _merge_candidates(self, candidates: Iterable[EntryCandidate]) -> List[EntryCandidate]:
        by_name: Dict[str, EntryCandidate] = {}
        for candidate in candidates:
            existing = by_name.get(candidate.function_name)
            if not existing:
                by_name[candidate.function_name] = candidate
                continue
            exposures = list(dict.fromkeys(existing.exposure.split("+") + candidate.exposure.split("+")))
            reasons = sorted(set(existing.reasons + candidate.reasons))
            prompts = [existing.custom_prompt, candidate.custom_prompt]
            existing.exposure = "+".join(exposures)
            existing.reasons = reasons
            existing.custom_prompt = " ".join(p for p in prompts if p)
            existing.confidence = max(existing.confidence, candidate.confidence)
        return list(by_name.values())

    @staticmethod
    def _find_calls(code: str, names: Sequence[str]) -> List[str]:
        stripped = re.sub(r"^\s*\d+\s*\|\s*", "", code, flags=re.MULTILINE)
        hits = []
        for name in names:
            if name == "argv":
                pattern = r"\bargv\b"
            else:
                pattern = rf"\b{re.escape(name)}\s*\("
            if re.search(pattern, stripped):
                hits.append(name)
        return hits

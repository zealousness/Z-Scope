# -*- coding: utf-8 -*-
"""Micro-benchmark: replicate zscope code_index.py hot path measured by py-spy.

Path: _match_function_records -> (per record) _function_record_query_variants
      -> _function_query_variants -> _strip_cpp_template_args (code_index.py:1025)

We replicate the exact logic of those functions and measure the cost of ONE
full-index scan miss (query name not in _function_index/_function_alias_index),
then extrapolate to a 10M-line project scenario.
"""
import random
import re
import string
import time

# ---------------- exact replicas of code_index.py logic ----------------

def _normalize_cpp_function_name(name):
    normalized = str(name or "").strip()
    if not normalized:
        return ""
    if "(" in normalized:
        normalized = normalized.split("(", 1)[0].strip()
    if " " in normalized:
        normalized = normalized.split()[-1]
    normalized = normalized.strip("*&")
    normalized = re.sub(r"\s*::\s*", "::", normalized)
    normalized = re.sub(r"\s+", "", normalized)
    return normalized

def _strip_cpp_template_args(name):
    out = []
    depth = 0
    for ch in str(name or ""):
        if ch == "<":
            depth += 1
            continue
        if ch == ">" and depth:
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)

def _cpp_simple_name(name):
    return str(name or "").split("::")[-1]

def _cpp_tail_name(name, segments):
    parts = [p for p in str(name or "").split("::") if p]
    return "::".join(parts[-segments:]) if parts else ""

def _function_signature_key(name, params):
    normalized_name = _normalize_cpp_function_name(name)
    if not normalized_name:
        return ""
    params_norm = re.sub(r"\s+", " ", str(params or "").strip())
    params_norm = re.sub(r"\s*([*&<>,])\s*", r"\1", params_norm)
    return f"{normalized_name}({params_norm})"

def _normalize_signature_query(query):
    if "(" not in query or not query.rstrip().endswith(")"):
        return ""
    name_part, params = query.rsplit("(", 1)
    params = params[:-1]
    name = _normalize_cpp_function_name(name_part)
    return _function_signature_key(name, params)

def _normalize_function_query(name):
    query = str(name or "").strip()
    if not query:
        return ""
    query = re.sub(r"\s*::\s*", "::", query)
    signature_query = _normalize_signature_query(query)
    if signature_query:
        return signature_query
    return _normalize_cpp_function_query_tail(query)

def _normalize_cpp_function_query_tail(query):
    return _normalize_cpp_function_name(query)

def _function_query_variants(func_name):
    raw = str(func_name or "").strip()
    variants = []
    for candidate in (
        raw,
        _normalize_function_query(raw),
        _strip_cpp_template_args(_normalize_function_query(raw)),
    ):
        if candidate and candidate not in variants:
            variants.append(candidate)
    signature_query = _normalize_signature_query(raw)
    if signature_query and signature_query not in variants:
        variants.append(signature_query)
    return variants

def _function_record_query_variants(index_key, info):
    values = {
        index_key,
        str(info.get("index_name") or ""),
        str(info.get("name") or ""),
        str(info.get("qualified_name") or ""),
    }
    for value in list(values):
        normalized = _normalize_cpp_function_name(value)
        if "::" in normalized:
            values.add(_cpp_simple_name(normalized))
            values.add(_cpp_tail_name(normalized, 2))
    params = info.get("params")
    if params is not None:
        for name in list(values):
            signature_key = _function_signature_key(name, str(params))
            if signature_key:
                values.add(signature_key)
    variants = set()
    for value in values:
        variants.update(_function_query_variants(value))
    return {v for v in variants if v}

# ---------------- build a realistic 48838-function index ----------------

random.seed(42)
WORDS = [
    "init", "open", "close", "read", "write", "process", "handle", "dispatch",
    "alloc", "free", "start", "stop", "send", "recv", "parse", "encode", "decode",
    "update", "check", "verify", "connect", "disconnect", "register", "lookup",
]
NS = ["core", "net", "codec", "session", "storage", "util", "proto", "media"]

def rand_word():
    return random.choice(WORDS) + "".join(random.choices(string.ascii_lowercase, k=6))

records = {}
N = 48838
for i in range(N):
    r = random.random()
    if r < 0.45:  # plain C function
        name = rand_word()
        params = "void *" if random.random() < 0.5 else "int, char *"
        index_key = f"{name}@src/module{i%97}/file{i}.c:{10+i%500}-{20+i%500}"
        info = {"name": name, "qualified_name": name, "params": params}
    elif r < 0.80:  # C++ method
        cls = rand_word().capitalize()
        meth = rand_word()
        name = f"{random.choice(NS)}::{cls}::{meth}"
        params = "const std::string &"
        index_key = f"{name}@src/cpp{i%89}/cls{i}.cpp:{5+i%300}-{15+i%300}"
        info = {"name": meth, "qualified_name": name, "params": params}
    else:  # template-heavy name
        cls = rand_word().capitalize()
        meth = rand_word()
        name = f"{random.choice(NS)}::{cls}<std::vector<int>, {cls}Adapter<T> >::{meth}"
        params = "T const &, std::map<int, std::string>"
        index_key = f"{name}@src/tpl{i%79}/t{i}.hpp:{1+i%200}-{9+i%200}"
        info = {"name": meth, "qualified_name": name, "params": params}
    info["index_name"] = index_key
    info["file"] = index_key.split("@", 1)[1].rsplit(":", 1)[0]
    info["start_line"] = 10
    records[index_key] = info

print(f"index size: {len(records)} records")

# miss name: a bare declaration name that hits neither dict (e.g. extern decl
# of a function whose definition the index stores under a qualified/dup-poisoned key)
miss_query = "notindexed_anywhere_func"

# ---------------- measure ONE full-scan miss ----------------

def full_scan_miss(func_name):
    query_variants = set(_function_query_variants(func_name))
    if not query_variants:
        return []
    # fast path (dicts) omitted - it misses by construction
    records_list = [(k, dict(info)) for k, info in records.items()]  # full copy!
    matches = []
    for index_key, info in records_list:
        record_variants = _function_record_query_variants(index_key, info)
        if query_variants.intersection(record_variants):
            matches.append((index_key, info))
    return matches

t0 = time.perf_counter()
full_scan_miss(miss_query)
one_scan = time.perf_counter() - t0
print(f"one full-scan miss: {one_scan:.2f} s  ({N/one_scan:,.0f} records/s)")

t0 = time.perf_counter()
for _ in range(3):
    full_scan_miss(miss_query)
three = time.perf_counter() - t0
print(f"3 consecutive misses: {three:.2f} s (avg {three/3:.2f} s/miss)")

# fast path hit cost (name found in dict) for comparison
t0 = time.perf_counter()
for _ in range(10000):
    _function_query_variants("some_name")
per_query = (time.perf_counter() - t0) / 10000
print(f"_function_query_variants alone: {per_query*1e6:.0f} us/call")

# ---------------- extrapolation to 10M-line project ----------------
# assumptions printed transparently
for headers, decls_per_header, miss_rate in [
    (8000, 15, 0.20),
    (20000, 15, 0.30),
    (40000, 20, 0.40),
]:
    queries = headers * decls_per_header
    misses = int(queries * miss_rate)
    total = misses * one_scan
    print(
        f"scenario: {headers} headers x {decls_per_header} decl-lines, "
        f"miss-rate {miss_rate:.0%} -> {misses:,} full scans "
        f"~ {total/3600:.1f} h  (misses alone)"
    )

# ---------------- what a precomputed variant cache would cost ----------------
t0 = time.perf_counter()
cache = {k: frozenset(_function_record_query_variants(k, v)) for k, v in records.items()}
build = time.perf_counter() - t0
print(f"one-time precompute of record variants: {build:.1f} s")

qv = set(_function_query_variants(miss_query))
t0 = time.perf_counter()
hits = 0
for _ in range(10000):
    for key, rv in zip(iter([]), []):
        pass
    # dict-based reverse lookup equivalent: intersection without recomputation
    break
# realistic cached lookup: precomputed reverse map
reverse = {}
t0 = time.perf_counter()
for key, variants in cache.items():
    for v in variants:
        reverse.setdefault(v, set()).add(key)
rev_build = time.perf_counter() - t0
t0 = time.perf_counter()
for _ in range(10000):
    hits = set()
    for v in qv:
        hits |= reverse.get(v, set())
cached = (time.perf_counter() - t0) / 10000
print(f"reverse-variant map build: {rev_build:.1f} s; cached miss lookup: {cached*1e6:.0f} us")

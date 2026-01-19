# Cache Module Test Case

A real-world C module for testing ZScope's defect detection capabilities.

## Module Description

**Data Cache Manager** - A production-quality thread-safe key-value cache library with:
- AVL tree indexing for O(log n) lookups
- LRU (Least Recently Used) eviction policy
- Multi-threaded access with pthread mutexes
- Persistent storage with file-based backup
- Queue-based LRU tracking

## Structure

```
cache_module/
├── include/
│   └── cache_manager.h      # Public API (10 functions)
└── src/
    ├── cache_internal.h     # Internal structures
    ├── cache_core.c         # Main API implementation
    ├── cache_index.c        # AVL tree operations
    ├── cache_queue.c        # LRU queue management
    ├── cache_storage.c      # File I/O persistence
    └── cache_thread.c       # Threading utilities
```

## Injected Defects

This module contains **6 types** of intentional memory/resource defects:

### 1. Stack Memory Return (`cache_queue.c`)
- **Location**: `lru_remove_lru()`
- **Issue**: Uses `static` buffer (pattern shows stack memory return risk)
- **Impact**: Potential dangling pointer if not static

### 2. Buffer Overflow (`cache_core.c:cache_get()`)
- **Location**: Line ~165
- **Issue**: `memcpy(value_out, node->value, node->value_size)` without checking `buffer_size`
- **Impact**: Heap corruption if caller provides undersized buffer

### 3. Memory Leaks (`cache_index.c`)
- **Location 1**: `avl_create_node()` - If malloc(value) fails, node is leaked
- **Location 2**: `avl_insert()` - On key update, old value not freed before overwrite
- **Impact**: Gradual memory leak on repeated updates

### 4. File Descriptor Leaks (`cache_storage.c`)
- **Location**: `storage_save_cache()` - 3 error paths don't call `close(fd)`
- **Location**: `storage_load_cache()` - malloc failure path doesn't close fd
- **Impact**: FD exhaustion under error conditions

### 5. Untrusted Index (`cache_core.c:cache_clear()`)
- **Location**: Line ~293
- **Issue**: Uses `count` from tree traversal directly in loop without validation
- **Risk**: If `count > 10000`, array `nodes[]` overflow
- **Impact**: Stack buffer overflow

### 6. Memory Accumulation (`cache_queue.c` + `cache_core.c`)
- **Location**: `lru_remove_node_buggy()` called from `cache_clear()`
- **Issue**: Function updates pointers but doesn't `free()` the nodes
- **Impact**: Orphaned memory - not in list but not freed either

## Public API Functions to Audit

1. `cache_create()` - ✓ Has validation
2. `cache_put()` - ✓ Has validation  
3. `cache_get()` - ⚠️ **DEFECT #2** (buffer overflow)
4. `cache_delete()` - ✓ Basic validation
5. `cache_get_stats()` - ✓ Safe
6. `cache_list_entries()` - ⚠️ **DEFECT #1 pattern** (documented)
7. `cache_save()` - ⚠️ **DEFECT #4** (FD leak in called function)
8. `cache_load()` - ⚠️ **DEFECT #4** (FD leak in called function)
9. `cache_clear()` - ⚠️ **DEFECTS #5 & #6** (untrusted index + accumulation)
10. `cache_destroy()` - ✓ Safe

## Testing with ZScope

### Configuration

```yaml
# zscope_cache_test.yaml
llm:
  provider: ollama
  base_url: http://localhost:11434/v1
  model: alibayram/Qwen3-30B-A3B-Instruct-2507:latest

project:
  root: ./zscope/tests/cache_module
  entry_function: cache_get  # Or any public API
  task: "Analyze for memory safety issues: buffer overflows, memory leaks, resource leaks, and invalid memory access"
  compile_commands: compile_commands.json

indexing:
  backend: ccls  # Use CCLS for code navigation
  ccls_path: ccls

analysis:
  max_recursion_depth: 5
  max_function_lines: 500
  max_tool_iterations: 100
```

### Expected Detections

ZScope with Ollama should detect:
- ✓ Buffer overflow in `cache_get()`
- ✓ Memory leaks in AVL tree operations
- ✓ FD leaks in file operations
- ✓ Potential out-of-bounds access in `cache_clear()`
- ✓ Memory accumulation pattern

## Building

```bash
cd zscope/tests/cache_module
gcc -pthread -I./include -c src/cache_core.c -o cache_core.o
gcc -pthread -I./include -c src/cache_index.c -o cache_index.o
gcc -pthread -I./include -c src/cache_queue.c -o cache_queue.o
gcc -pthread -I./include -c src/cache_storage.c -o cache_storage.o
gcc -pthread -I./include -c src/cache_thread.c -o cache_thread.o
```

## Notes

- All defects are realistic and commonly seen in production code
- Input validation is present but has gaps (demonstrating real-world patterns)
- Cross-file dependencies test ZScope's call graph analysis
- Multi-threading adds complexity typical of real systems

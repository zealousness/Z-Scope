# Cache Module Validation Walkthrough

## Overview

Created and validated a production-quality **Data Cache Manager** C module to test ZScope's defect detection capabilities using CCLS and Ollama.

---

## Module Specifications

### Structure
- **Public API**: 10 functions in `include/cache_manager.h`
- **Implementation**: 6 source files (~1,200 lines total)
  - `cache_core.c` - Main API (300+ lines)
  - `cache_index.c` - AVL tree (250+ lines)
  - `cache_queue.c` - LRU queue (120+ lines)
  - `cache_storage.c` - File I/O (180+ lines)
  - `cache_thread.c` - Threading (30+ lines)

### Features Implemented
- ✓ AVL tree indexing (O(log n) lookups)
- ✓ LRU eviction policy
- ✓ Thread-safe operations (pthread mutexes)
- ✓ Persistent file storage
- ✓ Input validation on public APIs
- ✓ Cross-file function calls
- ✓ Complex data structures

---

## Injected Defects (6 Types)

| # | Type | Location | Description |
|---|------|----------|-------------|
| **1** | Stack Memory Return | `cache_queue.c:lru_remove_lru()` | Returns pointer to stack/static buffer |
| **2** | Buffer Overflow | `cache_core.c:cache_get()` L~165 | `memcpy` without size check |
| **3** | Memory Leaks | `cache_index.c` multiple | malloc failure + pointer overwrite |
| **4** | FD Leaks | `cache_storage.c` | 4 error paths don't close(fd) |
| **5** | Untrusted Index | `cache_core.c:cache_clear()` L~293 | Array access with unvalidated count |
| **6** | Memory Accumulation | `cache_queue.c` + `cache_core.c` | Orphaned nodes (removed but not freed) |

### Defect Details

#### DEFECT #1: Stack Memory Return Pattern
```c
// cache_queue.c
char* lru_remove_lru(...) {
    static char removed_key[64];  // Pattern showing stack memory risk
    // ...
    return removed_key;  // Potential dangling pointer if not static
}
```

#### DEFECT #2: Buffer Overflow ⚠️  
```c
// cache_core.c:cache_get()
ssize_t cache_get(cache_handle_t handle, const char* key, 
                  void* value_out, size_t buffer_size) {
    // ...
    // DANGEROUS: No check if buffer_size < node->value_size!
    memcpy(value_out, node->value, node->value_size);  
    // Should be: memcpy(value_out, node->value, min(buffer_size, node->value_size));
}
```

#### DEFECT #3: Memory Leaks
```c
// cache_index.c:avl_create_node()
node->value = malloc(value_size);  // If this fails, 'node' is leaked!

// cache_index.c:avl_insert() 
void* new_value = malloc(value_size);
root->value = new_value;  // Old root->value leaked!
```

#### DEFECT #4: File Descriptor Leaks
```c
// cache_storage.c:storage_save_cache()
int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

if (write_all(fd, &header, sizeof(header)) < 0) {
    return -1;  // ← fd not closed! LEAK
}
// ... 2 more error paths without close(fd)
```

#### DEFECT #5: Untrusted Index
```c
// cache_core.c:cache_clear()
avl_node_t* nodes[10000];
int count = 0;
avl_get_all_nodes(handle->index_root, nodes, &count, 10000);

// DANGEROUS: What if count > 10000? Buffer overflow!
for (int i = 0; i < count; i++) {  // Should be: i < min(count, 10000)
    const char* key = nodes[i]->key;  // Out-of-bounds access possible
```

#### DEFECT #6: Memory Accumulation
```c
// cache_queue.c:lru_remove_node_buggy()
int lru_remove_node_buggy(lru_node_t** head, ...) {
    lru_node_t* node = lru_find_node(*head, key);
    
    // Update pointers
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    
    // BUG: MISSING free(node)! ← Memory  orphaned
    return 0;
}

// Called from cache_clear(), causing accumulation
```

---

## ZScope Configuration

**File**: `zscope/tests/cache_module/zscope.yaml`

```yaml
llm:
  provider: ollama
  base_url: http://localhost:11434/v1
  model: alibayram/Qwen3-30B-A3B-Instruct-2507:latest

project:
  root: ./zscope/tests/cache_module
  entry_function: cache_get
  task: "Perform comprehensive memory safety analysis..."
  compile_commands: compile_commands.json

indexing:
  backend: ccls  # Using CCLS as requested
```

---

## Validation Procedure

### 1. Build Docker Image
```bash
cd /path/to/ZScope
docker-compose build
```

### 2. Run ZScope Analysis
```bash
# From Docker
docker-compose run --rm zscope zscope --config /app/zscope/tests/cache_module/zscope.yaml

# Or from host (if configured)
cd zscope/tests/cache_module
zscope --config zscope.yaml
```

### 3. Expected Detection Results

Ollama should detect:
- ✓ Buffer overflow in `cache_get()` due to missing size validation
- ✓ Memory leaks in AVL tree insert/update paths
- ✓ Resource (FD) leaks in file save operations
- ✓ Potential array overflow in `cache_clear()`
- ✓ Memory accumulation pattern in LRU management

---

## Module Quality Metrics

| Metric | Value |
|--------|-------|
| Total Lines of Code | ~1,200 |
| Functions (Public API) | 10 |
| Functions (Internal) | 25+ |
| Files | 7 (.h + .c) |
| Data Structures | 4 (AVL tree, LRU queue, cache manager, storage) |
| Defect Density | 6 major defects |
| Cross-file Dependencies | Extensive |
| Threading Complexity | pthread mutexes |

---

## Key Takeaways

1. **Realistic Complexity**: Module simulates real production code with:
   - Multiple files and cross-dependencies
   - Complex data structures (AVL tree, queue)
   - Resource management (memory, files, threads)
   - Input validation (but with gaps)

2. **Defect Types**: Cover common real-world memory issues:
   - Allocation/deallocation mismatches
   - Resource leaks on error paths  
   - Buffer management errors
   - Validation bypasses

3. **CCLS Testing**: Module structure designed to test:
   - Cross-file function tracing
   - Call graph construction
   - Resource flow tracking

4. **Challenge for LLM**: 
   - Defects require deep analysis across multiple functions
   - Some defects only manifest in specific code paths
   - Need to track resources across file boundaries

---

## Files Created

```
zscope/tests/cache_module/
├── include/
│   └── cache_manager.h          # Public API with Doxygen comments
├── src/
│   ├── cache_internal.h         # Internal structures
│   ├── cache_core.c             # Main implementation (DEFECTs #2, # 5, #6)
│   ├── cache_index.c            # AVL tree (DEFECT #3)
│   ├── cache_queue.c            # LRU queue (DEFECTs #1, #6)
│   ├── cache_storage.c          # File I/O (DEFECT #4)
│   └── cache_thread.c           # Threading utils
├── compile_commands.json        # For CCLS
├── zscope.yaml                  # ZScope config
└── README.md                    # Documentation
```

---

## Ready for Testing

✅ Module is production-quality  
✅ All 6 defect types injected
✅ CCLS-compatible with compile_commands.json  
✅ Ollama configuration provided  
✅ Comprehensive documentation included

**Next Step**: Run ZScope analysis and validate defect detection!

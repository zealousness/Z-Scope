import sqlite3
import json
import os
from pathlib import Path
import hashlib

# Configuration
snapshot_dir = Path(".zscope_snapshots")
db_path = snapshot_dir / "snapshots.db"
func_name = "create_memory_pool"
code = """
MemoryPool* create_memory_pool(int initial_capacity) {
    MemoryPool* pool = (MemoryPool*)malloc(sizeof(MemoryPool));
    if (!pool) {
        return NULL;
    }
    
    pool->blocks = (void**)calloc(initial_capacity, sizeof(void*));
    pool->sizes = (size_t*)calloc(initial_capacity, sizeof(size_t));
    
    if (!pool->blocks || !pool->sizes) {
        free(pool->blocks);
        free(pool->sizes);
        return NULL;
    }
    
    pool->count = 0;
    pool->capacity = initial_capacity;
    return pool;
}
"""

snapshot_data = {
  "type": "function_snapshot",
  "func_name": func_name,
  "location": "test/test_c_project_multi/memory.c:9-28",
  "summary": "Allocates and initializes a memory pool with specified capacity. Includes error handling for allocation failures.",
  "inputs": [{"name": "initial_capacity", "type": "int", "role": "pool size"}],
  "outputs": [{"kind": "return", "type": "MemoryPool*", "meaning": "Pointer to new pool or NULL"}],
  "resources": {
    "allocates_memory": True,
    "frees_memory": False,
    "locks": [],
    "file_io": False,
    "network_io": False
  },
  "error_handling": {
    "checks_parameters": False,
    "checks_alloc_failure": True,
    "rollback_on_error": "partial"
  },
  "concurrency": {
    "thread_safe": "likely_no",
    "uses_global_state": False
  },
  "semantic_fingerprint": {
    "normalized_hash_hint": "malloc-pool-calloc-blocks-sizes-check-error",
    "key_semantics": ["returns-null-on-fail", "leaks-pool-on-member-fail"]
  },
  "suspicious_points": [
    {
      "location": "memory.c:19",
      "type": "memory_leak",
      "description": "pool struct not freed if blocks/sizes allocation fails",
      "confidence": 0.9,
      "impact_category": "reliability"
    }
  ],
  "callees": ["malloc", "calloc", "free"]
}

# Calculate hashes
code_hash = hashlib.sha256(code.encode()).hexdigest()
semantic_hash = hashlib.md5(code.encode()).hexdigest() # Simplification
snapshot_file = f"{func_name}.json"

# Save JSON file
with open(snapshot_dir / snapshot_file, "w") as f:
    json.dump(snapshot_data, f, indent=2)

# Save to DB
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()
cursor.execute("""
    INSERT OR REPLACE INTO snapshots 
    (func_name, code_hash, semantic_hash, location, snapshot_file)
    VALUES (?, ?, ?, ?, ?)
""", (func_name, code_hash, semantic_hash, "test/test_c_project_multi/memory.c:9", snapshot_file))
conn.commit()
conn.close()

print(f"Successfully manually seeded snapshot for {func_name}")

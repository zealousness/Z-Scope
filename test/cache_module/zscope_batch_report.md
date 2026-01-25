# Z-SCOPE Batch Analysis Report

## Summary
- **Functions Analyzed**: 5
- **Issues Found**: 2
- **No Issues Found**: 3
- **Errors**: 0
- **Total Issues Detected**: 2

## Function Details

| Function | Verdict | Issues | Duration |
| :--- | :--- | :--- | :--- |
| cache_clear | no_issue_found | 0 | 75.0s |
| cache_create | no_issue_found | 0 | 43.7s |
| cache_get | no_issue_found | 0 | 45.7s |
| cache_put | issues_found | 1 | 111.5s |
| cache_save | issues_found | 1 | 74.1s |

## Detected Issues

### Entry Function: `cache_put`

#### 1. [HIGH] ISSUE_1: cache_put
- **Location**: `src\cache_core.c:88`
- **Confidence**: `0.90`
- **Category**: memory_safety (use_after_free)
- **Relevant Code**:
```c
char* lru_key = lru_remove_lru(&handle->lru_head, &handle->lru_tail);
        if (lru_key) {
            handle->index_root = avl_delete(handle->index_root, lru_key);
            handle->stats.total_entries--;
        }
```
- **Description**: 在缓存满且需要淘汰LRU节点时，存在使用已释放内存的风险。
- **Root Cause**: lru_remove_lru函数返回静态变量的指针，而该静态变量在函数返回后仍然有效，但其内容可能被其他操作修改，导致在avl_delete中使用时出现未定义行为。
- **Suggested Fix**: 修改lru_remove_lru函数，使其返回动态分配的内存，而不是静态变量。或者，将lru_remove_lru函数改为返回一个结构体，其中包含要删除的键值，而不是直接返回键值字符串。

### Entry Function: `cache_save`

#### 1. [HIGH] ISSUE_1: cache_save
- **Location**: `src\cache_core.c:258`
- **Confidence**: `0.95`
- **Category**: resource_leak (file_descriptor_leak)
- **Relevant Code**:
```c
int result = storage_save_cache(handle->storage_path, handle->index_root);

    thread_unlock(handle);
    
    return result;
```
- **Description**: 在 cache_save 函数中，当 storage_save_cache 函数返回错误时，没有正确释放文件描述符，导致文件描述符泄露。
- **Root Cause**: cache_save 函数没有对 storage_save_cache 的返回值进行充分的错误处理，当存储操作失败时，没有确保文件描述符被正确关闭。
- **Suggested Fix**: 在调用 storage_save_cache 后，应该检查其返回值。如果返回错误，应该在解锁前确保文件描述符被关闭，或者在 storage_save_cache 函数内部确保即使发生错误也能正确关闭文件描述符。

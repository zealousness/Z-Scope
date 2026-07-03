# C Memory And Concurrency Patterns

This catalogue defines the C bug patterns Z-SCOPE should recognize in real
projects and in benchmark fixtures. A useful fixture should look like ordinary
C code: public APIs, parsers, worker threads, callbacks, registries, queues,
resource cleanup and error paths.

## 1. Audit Questions

For any object, buffer, file descriptor, lock or callback context, answer:

1. Where is it created?
2. Who owns it after creation?
3. How is ownership transferred or borrowed?
4. Which paths may release it?
5. Can another thread still observe it after release?
6. Are all error paths, retry paths and cleanup paths covered?
7. Which lock, atomic or reference-count protocol protects it?
8. Is the protocol documented or only implied by naming?

## 2. Memory Patterns

| Pattern | Typical trigger | What to prove |
| --- | --- | --- |
| null dereference | `malloc`, `fopen`, `strchr`, map lookup then immediate dereference | failure result can be NULL and no guard dominates use |
| uninitialized pointer/read | local pointer or struct field conditionally initialized | use path skips initialization |
| use after free | `free/close/munmap` followed by dereference, copy, return, callback or event use | release-to-use path is feasible and no reassignment/ownership transfer breaks it |
| double free | same pointer released twice or released in branch then cleanup label | both releases can occur for the same object |
| invalid free | freeing stack/global/offset pointer | pointer is not the base returned by an allocator |
| leak | allocation followed by early return or overwritten pointer | object is owned locally and not released/transferred on an exit |
| realloc misuse | `p = realloc(p, n)` or old alias used after realloc | old object is leaked on failure or stale alias remains |
| integer overflow | `count * sizeof(T)`, `len + header`, `offset + size` before allocation/copy | arithmetic can wrap before a protective check |
| bounds read/write | `memcpy`, `memmove`, `strcpy`, array index, parser length field | source length and destination capacity are inconsistent |
| off by one | `<= len`, terminator at `buf[len]`, allocation missing NUL | maximum valid index is exceeded by one |
| signed/unsigned misuse | `int n = read(...); memcpy(..., n)` | negative value can convert to huge unsigned size |
| stack overflow | large stack arrays, input-controlled VLA, recursion | stack use is attacker-controlled or too large |
| stack escape | returning local address or passing it to thread/callback/timer | callee may outlive the stack frame |
| type/alignment issue | wire data cast to struct/int pointer | alignment, aliasing or actual type is not guaranteed |
| padding disclosure | sending uninitialized stack struct | padding or partially initialized fields reach output |

## 3. Resource Lifecycle Patterns

| Pattern | Typical trigger | What to prove |
| --- | --- | --- |
| file/socket leak | `open/fopen/socket` without close on all exits | ownership is not transferred and cleanup is missing |
| stale fd | `close(fd)` while watcher/global still stores fd | later event/read/write can operate on reused fd |
| mmap UAF | `munmap(ptr)` while global pointer/length remains | later reader can access unmapped memory |
| init/deinit mismatch | partial initialization then full destroy | destroy can release uninitialized fields or miss initialized fields |
| start/stop mismatch | thread or service started before full init or destroyed before join | worker may access freed or half-initialized state |
| registry/plugin stale callback | unregister/unload while dispatch can still call callback | function pointer/context outlives module/object |
| ownership transfer ambiguity | `insert/remove/push/pop/take/borrow` without clear contract | caller and callee disagree on who releases |
| retry/recovery cleanup | release partial state then retry | stale state or repeated release crosses attempts |

## 4. Concurrency Patterns

| Pattern | Typical trigger | What to prove |
| --- | --- | --- |
| data race | global/static/shared struct read or write without same lock/atomic | at least one writer and concurrent access are possible |
| non-atomic refcount | `refcnt++`, `--refcnt == 0` outside lock/atomic | concurrent get/put can lose updates or free too early |
| check then act | `if (obj) use(obj)` without lifetime protection | object can change between check and use |
| pathname TOCTOU | `access/stat/lstat` followed by `open/fopen/unlink` | path can be swapped between check and use |
| missing unlock | lock followed by return/goto/break without unlock | exit path leaves lock held |
| recursive deadlock | helper called under lock also takes same non-recursive lock | same thread can block on the same mutex |
| lock order inversion | paths acquire A then B and B then A | both paths are reachable concurrently |
| callback/IO under lock | lock held while calling external callback, blocking IO or join | callback may reenter or block while lock is held |
| condition wait bug | `pthread_cond_wait` guarded by `if` | spurious wakeup or lost wakeup can violate predicate |
| double-checked locking | unsynchronized first read of lazy global | reader can observe partially initialized object |
| object publication | global/container assignment before full init | other thread can see half-initialized object |
| mutex/cond destroy race | destroy before all workers stopped | other thread can still lock/wait |

## 5. Higher-Level Lifecycle Shapes

Real C projects often hide bugs in these shapes:

- API create/use/destroy pairs
- message or opcode dispatch handlers
- event loops and fd watchers
- asynchronous callbacks and completion contexts
- timer cancellation and delayed callbacks
- queues between producer and worker threads
- object pools and slab-style reuse
- cache/singleton reload or hot config swap
- mmap/shared-memory rule tables
- signal handlers and interrupt-like callbacks
- ring buffers with head/tail indices
- RCU, epoch or delayed-free schemes

Benchmarks should include both positive and negative examples for these shapes.
Negative examples matter: without them, a scanner can overfit on suspicious
keywords and look good only on recall.

## 6. Mapping To Z-SCOPE Skills

| Pattern family | Skill |
| --- | --- |
| bounds, integer, copy, alignment, uninitialized read | `bounds_and_integer` |
| leak, stale fd, mmap lifecycle, cleanup | `resource_lifecycle` |
| UAF, double free, invalid free | `temporal_memory` |
| NULL and unchecked failures | `null_and_failure` |
| stack address escape | `stack_escape` |
| lock order, missing unlock, recursive deadlock | `concurrency_lock_order` |
| shared state, check-use, refcount, condvar | `shared_state_race` |
| ownership/borrow/transfer contract | `ownership_contract` |
| string building, format string, shell command | `string_and_format` |

`test/range` should remain a compact regression fixture, not a complete corpus.
When a production bug pattern is added here, either add a range case or document
why it needs a larger real-project fixture.

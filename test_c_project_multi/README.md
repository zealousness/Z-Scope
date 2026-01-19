# Multi-file C Test Project

This project demonstrates cross-file function calls and various code defects for testing ZScope's analysis capabilities.

## Structure

- `main.c` - Entry point, calls functions from all modules
- `utils.c/h` - String and memory utilities
- `memory.c/h` - Memory pool management  
- `processor.c/h` - Data packet processing
- `compile_commands.json` - Compilation database

## Intentional Defects

### utils.c
- `safe_malloc()`: Continues after allocation failure instead of returning NULL

### memory.c  
- `create_memory_pool()`: Memory leak when allocation fails (pool not freed)
- `resize_buffer()`: Old buffer not freed, causing memory leak

### processor.c
- `create_packet()`: No bounds checking on strcpy() - buffer overflow risk
- `process_batch()`: Memory leaks on error paths (allocated packets not freed)

## Cross-file Call Graph

```
main()
├─> safe_strdup() [utils.c]
├─> safe_strlen() [utils.c]
├─> create_memory_pool() [memory.c]
├─> pool_alloc() [memory.c]
├─> free_memory_pool() [memory.c]
├─> create_packet() [processor.c]
│   ├─> safe_malloc() [utils.c]
│   └─> create_buffer() [memory.c]
│       └─> safe_malloc() [utils.c]
├─> process_packet() [processor.c]
├─> free_packet() [processor.c]
├─> process_batch() [processor.c]
│   ├─> create_packet() [processor.c]
│   ├─> process_packet() [processor.c]
│   └─> free_packet() [processor.c]
├─> create_buffer() [memory.c]
└─> resize_buffer() [memory.c]
```

## Building

```bash
gcc -c utils.c -I.
gcc -c memory.c -I.
gcc -c processor.c -I.
gcc -c main.c -I.
gcc -o test_program main.o utils.o memory.o processor.o
```

## Testing with ZScope

```bash
zscope --config ../zscope.yaml
```

Or with custom config:
```bash
zscope -p . -e main -t "Analyze for memory leaks and buffer overflows" \
  --base-url http://localhost:11434/v1 \
  --api-key "" \
  --compile-db compile_commands.json
```

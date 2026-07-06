# Task Dispatcher - Micro Benchmark Project

A C-based task dispatcher system designed for testing static analysis and AI code auditing tools.

## Project Structure

```
task_dispatcher/
├── include/              # Public headers
│   ├── types.h          # Complex type definitions
│   ├── task_dispatcher.h # Public API
│   └── common.h         # Common macros and utilities
├── internal/            # Private headers (.ph files)
│   ├── types.ph
│   ├── network.ph
│   ├── parser.ph
│   ├── plugin.ph
│   └── executor.ph
├── src/                # Source files
│   ├── main.c
│   ├── utils.c
│   ├── network.c
│   ├── parser.c
│   ├── plugin.c
│   └── executor.c
├── Makefile
├── GROUND_TRUTH.md      # Vulnerability documentation
└── README.md
```

## Building

### Prerequisites

- GCC or Clang compiler
- pthread library
- Make build system

### Compilation

```bash
# Build the project
make

# Clean build artifacts
make clean

# Run the program
make run

# Run tests
make test
```

### Generate compile_commands.json

For use with Clang-based tools:

```bash
# Install bear (if not already installed)
# Ubuntu/Debian: sudo apt-get install bear
# macOS: brew install bear

# Generate compile_commands.json
bear make
```

## Usage

### Basic Usage

```c
#include "task_dispatcher.h"

int main() {
    // Initialize dispatcher
    const char* config = "{ \"queue_size\": 256, \"thread_count\": 4 }";
    td_init(config);
    
    // Register a plugin
    td_register_plugin("my_plugin", my_task_handler);
    
    // Submit a task
    td_execute_command("echo 'Hello World'");
    
    // Cleanup
    td_cleanup();
    
    return 0;
}
```

### Command Line

```bash
# Run with default command
./build/task_dispatcher

# Run with custom command
./build/task_dispatcher "ls -la"
```

## Public API

### `int td_init(const char* config_str)`

Initialize the task dispatcher with JSON configuration.

### `int td_submit_task(const void* task_data, size_t data_len)`

Submit a task to the dispatcher queue.

### `int td_register_plugin(const char* plugin_name, task_handler_t handler_fn)`

Register a plugin handler for tasks.

### `int td_execute_command(const char* command)`

Execute a command through the dispatcher.

### `int td_query_status(task_id_t task_id)`

Query the status of a submitted task.

### `int td_unregister_plugin(const char* plugin_name)`

Unregister a previously registered plugin.

### `int td_cleanup(void)`

Cleanup and shutdown the dispatcher.

### Runtime maintenance APIs

The runtime maintenance surface also includes stream-journal and lock-cache
entry points used by the benchmark:

- `td_runtime_process_stream_batch(...)`
- `td_runtime_maintain_lock_cache(...)`

## Security Testing

This project contains intentionally planted security vulnerabilities for testing purposes. The current benchmark contains 139 scored findings. See `GROUND_TRUTH.md` for complete documentation and `benchmark/PATTERN_COVERAGE.md` for the C memory/concurrency pattern matrix.

### Vulnerability Categories

1. **Memory Corruption**: Bounds bugs, heap overflow, under-read/underwrite, off-by-one writes, stack overflow, integer overflow, signed/unsigned conversion, format string
2. **Lifetime Issues**: Use-after-free, double free, memory leak, null pointer dereference, invalid free, stale fd, stale mmap pointer, expired pointer
3. **Concurrency and Resources**: Data race, refcount race, deadlock, missing/invalid unlock, lost wakeup, unsafe publication, callback under lock, TOCTOU, resource allocation without limits

### Testing Tools

Recommended static analysis tools:
- Clang Static Analyzer: `scan-build make`
- Cppcheck: `cppcheck --enable=all src/`
- Coverity: Commercial tool

Recommended dynamic analysis tools:
- Valgrind: `valgrind --leak-check=full ./build/task_dispatcher`
- AddressSanitizer: `make CFLAGS="-fsanitize=address -g"`
- ThreadSanitizer: `make CFLAGS="-fsanitize=thread -g"`

## License

This is a benchmark project for security research purposes.

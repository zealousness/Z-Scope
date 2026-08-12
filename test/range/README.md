# Range C/C++ fixture

This directory is the source fixture for the C/C++ benchmark. It intentionally
contains unsafe code and must not be treated as a production sample or repaired
during ordinary product work.

`CMakeLists.txt` is the only supported build contract. On Windows, use the
canonical command below; it automatically restarts C/C++ execution inside WSL.

```bash
zscope-benchmark run --language c_cpp --mode smoke
```

The runner scans an allowlisted copy of the fixture. Files under `benchmark/`
are maintenance and scoring assets and never enter the scan context.

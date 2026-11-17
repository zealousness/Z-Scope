# Range Java fixture

This directory is the source fixture for the Java benchmark. It intentionally
contains unsafe code and must not be used as a production example or repaired
during ordinary product work.

Maven (`pom.xml`) is the build contract. Run the answer-free structural smoke
path with:

```bash
zscope-benchmark run --language java --mode smoke
```

The runner scans an allowlisted copy of the fixture. Ground truth and maintenance
coverage data remain outside the scan context.

XStream is pinned to 1.4.21 to fix CVE-2024-47072 in its binary stream reader.
The fixture still exercises the original XML deserialization API; upgrading the
library does not remove its intentionally unsafe source patterns or alter truth.

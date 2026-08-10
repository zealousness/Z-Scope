# Z-SCOPE JavaParser Structure Frontend

This is the repo-local JavaParser sidecar used by
`java_structure_frontend: auto` after Spoon is unavailable or fails.

Build:

```bash
mvn -q -DskipTests package
```

Run:

```bash
java -jar target/zscope-java-structure-javaparser-0.1.0.jar \
  --project-root /path/to/project \
  /path/to/project
```

The exporter emits the Z-SCOPE Java structure JSON contract with
`frontend=javaparser` and `precision=source_level_approx`. It is an AST-level
source structure frontend and does not perform full Maven type solving, data
flow, or taint analysis.

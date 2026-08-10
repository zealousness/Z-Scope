# Z-SCOPE Java Structure Spoon Exporter

This is the production Spoon sidecar for the Java structure frontend.

Build:

```bash
cd tools/java-structure-spoon
mvn -q -DskipTests package
```

Run:

```bash
java -jar target/zscope-java-structure-spoon-0.1.0.jar \
  --project-root /path/to/project \
  --lombok-processor auto \
  /path/to/project
```

Z-SCOPE config:

```yaml
indexing:
  backend: java_source
  java_structure_frontend: spoon
  java_structure_extractor_command:
    - java
    - -jar
    - tools/java-structure-spoon/target/zscope-java-structure-spoon-0.1.0.jar
    - --project-root
    - "{source_root}"
    - "{source_root}"
```

The exporter always uses Spoon `MavenLauncher`, which lets Maven resolve source
folders and project dependencies. This requires `mvn` to be available on `PATH`
at runtime and a `pom.xml` under the project root.

Lombok support:

- `--lombok-processor auto` is the default. The exporter enables Lombok's JDT
  annotation processor when the project `pom.xml` references Lombok or source
  files contain common Lombok imports/annotations such as `@Slf4j`, `@Data`,
  `@Getter`, or `@Builder`.
- `--lombok-processor on` forces Lombok annotation processing.
- `--lombok-processor off` keeps the raw Spoon/JDT behavior.

When Lombok processing is enabled, the sidecar records
`lombok.launch.AnnotationProcessorHider$AnnotationProcessor`, adds the bundled
Lombok jar to the Spoon source classpath, and switches Spoon/JDT into
no-classpath-tolerant modeling for Lombok projects. This avoids the common
`log cannot be resolved` failure in projects that rely on `@Slf4j` and similar
annotations. The exporter also adds synthetic `log` field facts for common
Lombok logger annotations (`@Slf4j`, `@Log4j2`, `@Log`, `@CommonsLog`,
`@XSlf4j`) when Spoon does not expose a generated `CtField`.

Why not always use Lombok's ECJ javaagent directly? Current Spoon 11.4.0 embeds
Eclipse JDT/ECJ 3.46.0, while Lombok's ECJ patch path can still fail with an
`argument type mismatch` inside `PatchFixesHider$Transform`. The sidecar keeps
the processor metadata and classpath integration, but uses Spoon's no-classpath
tolerance as the deterministic in-process fallback instead of delombok.

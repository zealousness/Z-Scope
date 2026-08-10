# Java Range Full-Category Maven Benchmark

`test/java_range` is the Java regression benchmark for the current Z-SCOPE Java
route: Maven resolves real dependencies, `java_structure_frontend: auto`
selects the best available source frontend, local Java rules provide
deterministic security signals, and SootUp/WALA/Joern provide the default
program-analysis evidence. The LLM validates evidence. CodeQL is an optional
user-supplied comparison signal and is never distributed.

## Current Route

- Build and classpath: Maven.
- Structure frontend: auto fallback chain, normally Spoon `MavenLauncher` for this Maven fixture.
- Z-SCOPE backend: `java_unified`.
- Signal layer: Java local rules plus SootUp/WALA/Joern; this benchmark may enable user-supplied CodeQL explicitly.
- Validation layer: LLM evidence audit and report validation.

## Coverage

The fixture covers these Java areas:

- Web: Controller, Service, Mapper, DTO, Filter, Interceptor, Security config.
- Generic Java: CLI args, public APIs, message listener, batch env, stdin.
- Persistence: JDBC, JPA/JPQL, Mongo/NoSQL, LDAP, JNDI.
- Parser/runtime: Java native deserialization, Fastjson, SnakeYAML, XStream, XML, Freemarker, MVEL, regex, Zip, reflection, class loading, classpath resources.
- Crypto/security: weak crypto, fixed IV/seed, JWT decode, weak random, TLS verifier bypass, hardcoded secret.
- Resource/concurrency: unclosed resource, `readAllBytes`, temp files, insecure file permissions, shared mutable static state.

Ground truth version 5 covers every current `JavaRule.rule_id` in
`zscope/core/candidates/java_rules.py`, plus the benchmark-specific
`AdminInterceptor` authorization finding. `JwtBypassFilter` is now covered by
the real `java_filter_unconditional_chain` local rule instead of a custom
benchmark-only rule. The manifest currently has 58 truth records covering 49
rule IDs and keeps
independent GT records for repeated-but-distinct rule surfaces, including Java
native deserialization in `ParserEntry.nativeDeserialize`, hardcoded JWT HMAC
secret material in `JwtService.issueToken`, weak DES/ECB crypto in `CryptoEntry`,
world-writable permissions in `ResourceEntry`, and the standalone public XXE
surface in `ParserEntry.parseXml`.

## Dependencies

Maven downloads the real libraries declared in `pom.xml`, including Spring Web,
Spring Security, Spring Data JPA, Spring Kafka, MyBatis, Auth0 Java JWT, MongoDB
driver, Jackson, SnakeYAML, XStream, Fastjson2, Freemarker, Groovy, MVEL, and
Commons JEXL.

Java signal providers are enabled by this benchmark config, but they are not
auto-installed at runtime:

- Spoon/JavaParser structure frontends use Temurin/JDK 21 and Maven. The
  default Spoon invocation reuses the prepared local Maven cache so it can run
  offline. Use the sidecar's explicit `--force-refresh` option only while
  intentionally refreshing dependencies on a connected preparation host.
- SootUp uses JDK 21 and the repo runner jar built with `mvn -q -f tools/java-signal-sootup/pom.xml -DskipTests package`.
- WALA uses JDK 21 and the repo runner jar built with `mvn -q -f tools/java-signal-wala/pom.xml -DskipTests package`.
- CodeQL needs the user-installed CodeQL CLI in `PATH`, or an absolute path in `indexing.java_signal_provider_commands.codeql`.
- Joern needs the user-installed Joern CLI available as `joern` in `PATH`, or `indexing.joern_path` pointing to the executable.

Linux setup example:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-21-jdk maven unzip curl
mvn -q -f tools/java-structure-spoon/pom.xml -DskipTests package
mvn -q -f tools/java-structure-javaparser/pom.xml -DskipTests package
mvn -q -f tools/java-signal-sootup/pom.xml -DskipTests package
mvn -q -f tools/java-signal-wala/pom.xml -DskipTests package
```

Windows users run the matching Linux toolchain through WSL2. Native Windows is
useful for unit tests but does not produce a formal Java baseline.

Install Joern from its official distribution or your existing local toolchain,
then verify:

```bash
joern --version
```

## Signal Providers: Result And Runtime Impact

The single benchmark config uses:

```yaml
java:
  structure: [sootup, wala]
  signals: [joern]
```

These providers should be treated as evidence expansion:

- SootUp/WALA can add typed call edges and source/sink hints. This may improve
  cross-method evidence and recall, but it can also increase duplicate or
  approximate candidates that land in `needs_review`.
- Joern and CodeQL can add stronger CPG/path-problem evidence. This can improve
  validation quality for real flows, but raw provider alerts are still
  evidence-only and never bypass the Validator.
- Enabling more providers can raise both `with_needs_review` recall and review
  volume. Default-view precision should be checked separately because only
  validated, merged candidates should enter default issues.

Runtime impact:

| Config | Expected cost |
| --- | --- |
| `zscope.benchmark.yaml` with SootUp/WALA/Joern and optional BYO CodeQL | Current benchmark route; richer evidence and higher runtime cost. |
| SootUp or WALA | Adds JVM runner startup and source scan cost. Small fixtures are usually seconds; larger projects scale with source size and analyzed entries. |
| Joern | Adds Joern server startup, CPG import, and CPG query time. First import is the expensive part. |
| CodeQL | Adds CodeQL database creation/reuse plus query suite analysis. First database creation can take minutes on real Maven projects; full multi-entry scans may be much slower until shared SARIF caching is added. |

When comparing runs, record wall time and both benchmark views:

- `evaluation_views.default`: conservative final report.
- `evaluation_views.with_needs_review`: default plus review-only observations and uncertain but useful evidence.

Do not compare only raw issue counts. Compare TP, missed GT, effective FP,
duplicates, and time together.

## Acceptance Model

First-pass acceptance is structural and rule-oriented:

- Maven compile passes.
- Auto structure frontend picks Spoon when `pom.xml` and `mvn` are available, indexing all listed entries with `source_level_exact` precision.
- `benchmark/entries.json` and `benchmark/ground_truth.json` are internally consistent.
- The fixture source produces at least one Java local-rule candidate for every current Java rule.
- Full LLM benchmark Precision/Recall/F1 is recorded for observation; it is not a blocking first-pass acceptance gate.

The committed structural baseline is 58 truth records covering 49 rule IDs,
54 entries, and 48 Java rules with fixture coverage. There is no trustworthy committed LLM accuracy
baseline yet. The first Preview baseline requires five successful isolated cold
runs and published reproducible artifacts; it does not invent a precision gate.

## Java LLM Active Audit

Java scans now pass a compact `java_active_audit_context` to the
`vulnerability_analyzer`. It records the active structure frontend, entry kind,
component, annotations, framework sources/guards, reachable Java callees, Java
candidate signals, and unassigned Java worker tickets. The LLM should use this
context to actively audit Controller -> Service -> Mapper/helper flows, filters,
interceptors, parser/runtime helpers, crypto/JWT services, resources, and shared
state.

Focused Deep Worker planning also has Java-specific source rules. When
`analysis.enable_subagent_workers` is enabled, Java worker tickets use
`source=java_active_source_rule` and target the Java skills instead of the
C/C++ malloc/copy/lock trigger set.

## Known Limits

- The benchmark config enables SootUp/WALA/Joern signal providers. CodeQL is
  user-supplied and must be enabled explicitly. Missing runner jars, an
  unavailable Joern server, or an explicitly configured but missing CodeQL CLI
  are reported as degraded providers; Z-SCOPE does not download or install
  them during analysis.
- SootUp/WALA runner output is first-version typed static callgraph/source-sink evidence, not a replacement for full points-to/taint. CodeQL SARIF path-problem evidence is normalized to exact-flow candidates, but still goes through Validator.
- Some fixture findings are intentionally syntactic and must be validated by the LLM before they are reportable.
- Field-level cases such as hardcoded secrets and shared static state are represented through nearby public API entries for benchmark consistency. The analyzer attaches `java_shared_mutable_static_state` only to entries that actually touch the static field, with the declaration line as the primary coordinate and method access as sink evidence.
- Full benchmark scores may vary with model output; structure and rule coverage tests are the stable regression gate.
- LLM self-generated findings are not allowed to replace local-rule candidates;
  verified Java proof-carrying local-rule candidates can enter the default
  issue view at the Java evidence threshold.
- Java LLM-only active findings are marked
  `candidate_source=java_llm_active_audit` and
  `active_audit_review_only=true`. Even when the Validator verifies them, they
  stay in `needs_review` and appear in the `with_needs_review` dashboard view.
  If they match an existing local/backend candidate, they are attached as
  related/alternate evidence without changing the default issue boundary.
- Curated deterministic Java local rules such as command execution, NoSQL,
  template injection, ReDoS, reflection, dynamic class loading, classpath
  traversal, resource exhaustion, header injection, CORS, shared static state,
  JNDI lookup, manual close resource leaks, and unconditional servlet
  filter-chain continuation can enter the default view when the Validator
  verifies them with `final_score >= 0.60`.
- LLM self-generated extras and context-dependent observations still use the
  normal threshold or `needs_review` flow; they do not inherit the deterministic
  local-rule threshold.
- Java report coordinates are normalized before report assembly. If a Validator
  response places prose, C/C++ leftovers, or non-Java coordinates in
  `file`/`file_path`/`location`, Z-SCOPE recovers the Java source coordinate from
  the evidence pack, entry key, source, sink, or analyzed-from metadata.
- CORS policy evidence is accepted from either method/class annotations or
  framework semantics. If a structure frontend records `@CrossOrigin("*")` only
  as route/security metadata, the analyzer converts it to annotation-like
  context so `java_cors_wildcard` still points at the controller annotation line.
- MyBatis annotation mapper findings prefer mapper evidence over caller
  evidence. `@Select`/`@Insert`/`@Update`/`@Delete` `${...}` reports are
  attributed to the mapper annotation line, while the controller/service entry
  path is kept as supporting reachability context.
- Java active-audit observations normalize benchmark categories before scoring:
  hardcoded JWT/API-key evidence becomes `secret_exposure`, shared static
  `HashMap` evidence becomes `concurrency_race`, and unclosed stream evidence
  becomes `resource_leak`. Field-level roots prefer the declaration/literal line
  over a later wrapper method line.
- Java active-audit observations for open redirect, upload/path traversal, and
  weak crypto are recovered to the concrete Java source file when the evidence
  text names the benchmark root. If they duplicate an existing local/provider
  candidate, they attach as related review evidence rather than becoming
  independent effective FPs.
- Short Java coordinates such as `jwtbypassfilter.java:14` are upgraded to the
  more specific `src/main/java/...` coordinate when structured evidence carries
  the full source path. This keeps `java_filter_unconditional_chain` and similar
  rule findings from becoming duplicate effective FPs.
- Verified curated deterministic Java local rules with `0.55 <= final_score <
  0.60` are retained in `needs_review` instead of being downgraded to generic
  `uncertain`, so the `with_needs_review` view can still expose low-scored but
  deterministic evidence such as classpath resource traversal.
- Snapshot and final-report cache files use short stable hash-suffixed names.
  Long Java signatures such as Spring Security `securityFilterChain(...)` do not
  exceed filesystem filename limits.

## Local Verification

Run structure and rule checks without invoking an LLM:

```bash
mvn -q -f tools/java-structure-spoon/pom.xml -DskipTests package
mvn -q -f tools/java-structure-javaparser/pom.xml -DskipTests package
mvn -q -f tools/java-signal-sootup/pom.xml -DskipTests package
mvn -q -f tools/java-signal-wala/pom.xml -DskipTests package
mvn -q -f test/java_range/pom.xml -DskipTests package
PYTHONPATH=. pytest -q tests/test_java_range_benchmark.py tests/test_java_rule_candidates.py tests/test_java_source_backend.py
PYTHONPATH=. pytest -q tests/test_snapshot_store.py tests/test_validation_pipeline.py tests/test_issue_dedup.py tests/test_benchmark_protocol.py
python -m zscope.cli.cli -c test/java_range/zscope.benchmark.yaml --build-index --verbose
```

With SootUp/WALA jars built and Joern available, build-index
logs should show the configured providers. Missing providers should be
reported with a degraded reason instead of being auto-installed.

Run the full benchmark scan and score it:

```bash
export Z_SCOPE_API_KEY=...
rm -rf test/java_range/.zscope_knowledge test/java_range/.zscope_snapshots \
       test/java_range/.zscope_conversations test/java_range/zscope_batch_report.json \
       test/java_range/zscope_batch_report.md test/java_range/evaluation.json
python -m zscope.cli.cli -c test/java_range/zscope.benchmark.yaml --verbose \
  > test/java_range/zscope_run.log 2>&1
python scripts/external_benchmark.py evaluate \
  --report test/java_range/zscope_batch_report.json \
  --truth test/java_range/benchmark/ground_truth.json \
  --output test/java_range/evaluation.json \
  --line-tolerance 8
python -m json.tool test/java_range/evaluation.json
```

For active-audit review, inspect both:

- `evaluation_views.default`: proof-carrying local/backend findings only.
- `evaluation_views.with_needs_review`: default plus verified/uncertain Java
  active-audit observations.

Open the same Web dashboard entry used by C/C++ on port 8000:

```bash
zscope -c test/java_range/zscope.benchmark.yaml \
  --dashboard \
  --dashboard-host 0.0.0.0 \
  --dashboard-port 8000
```

Then browse to `http://localhost:8000`.

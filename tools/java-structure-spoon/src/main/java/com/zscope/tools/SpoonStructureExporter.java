package com.zscope.tools;

import spoon.MavenLauncher;
import spoon.SpoonAPI;
import spoon.SpoonModelBuilder;
import spoon.compiler.builder.JDTBuilder;
import spoon.reflect.CtModel;
import spoon.reflect.code.CtInvocation;
import spoon.reflect.cu.SourcePosition;
import spoon.reflect.declaration.CtAnnotation;
import spoon.reflect.declaration.CtConstructor;
import spoon.reflect.declaration.CtElement;
import spoon.reflect.declaration.CtExecutable;
import spoon.reflect.declaration.CtField;
import spoon.reflect.declaration.CtMethod;
import spoon.reflect.declaration.CtModifiable;
import spoon.reflect.declaration.CtParameter;
import spoon.reflect.declaration.CtType;
import spoon.reflect.declaration.ModifierKind;
import spoon.reflect.reference.CtExecutableReference;
import spoon.reflect.reference.CtTypeReference;
import spoon.reflect.visitor.filter.TypeFilter;
import spoon.support.compiler.jdt.JDTBasedSpoonCompiler;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class SpoonStructureExporter {
    private static final String LOMBOK_PROCESSOR = "lombok.launch.AnnotationProcessorHider$AnnotationProcessor";
    private static final Set<String> LOMBOK_MARKERS = Set.of(
        "import lombok.",
        "@Slf4j",
        "@Log4j2",
        "@Log",
        "@CommonsLog",
        "@XSlf4j",
        "@Data",
        "@Getter",
        "@Setter",
        "@Builder",
        "@SuperBuilder",
        "@NoArgsConstructor",
        "@AllArgsConstructor",
        "@RequiredArgsConstructor",
        "@Value",
        "@SneakyThrows",
        "@EqualsAndHashCode"
    );

    private SpoonStructureExporter() {
    }

    public static void main(String[] rawArgs) {
        Args args = null;
        int exitCode = 0;
        try {
            args = Args.parse(rawArgs);
            MavenLauncher launcher = createLauncher(args);
            launcher.getEnvironment().setComplianceLevel(args.compliance);
            launcher.getEnvironment().setNoClasspath(args.noClasspath);
            launcher.getEnvironment().setIgnoreDuplicateDeclarations(true);
            AnnotationProcessingState annotationProcessing = configureAnnotationProcessing(args, launcher);
            buildModel(launcher, args, annotationProcessing);
            CtModel model = launcher.getModel();
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("frontend", "spoon");
            payload.put("build", buildMetadata(args, launcher, annotationProcessing));
            payload.put("classes", exportTypes(model, args.sourceRoot));
            System.out.println(Json.write(payload));
        } catch (Exception exc) {
            System.err.println("Spoon structure export failed: " + exc.getMessage());
            exc.printStackTrace(System.err);
            exitCode = 2;
        } finally {
            cleanupMavenClasspathTemp(args);
        }
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    private static void cleanupMavenClasspathTemp(Args args) {
        if (args == null) {
            return;
        }
        try {
            Files.deleteIfExists(args.projectRoot.resolve("spoon.classpath.tmp"));
        } catch (IOException exc) {
            System.err.println("Unable to remove Spoon Maven classpath temp file: " + exc.getMessage());
        }
    }

    private static MavenLauncher createLauncher(Args args) {
        File pom = args.projectRoot.resolve("pom.xml").toFile();
        if (!pom.exists()) {
            throw new IllegalArgumentException("Spoon Maven frontend requires pom.xml under project root: " + args.projectRoot);
        }
        MavenLauncher launcher = new MavenLauncher(
            args.projectRoot.toString(),
            MavenLauncher.SOURCE_TYPE.ALL_SOURCE,
            args.forceRefresh
        );
        if (!args.classpath.isEmpty()) {
            launcher.getEnvironment().setSourceClasspath(args.classpath.toArray(new String[0]));
        }
        return launcher;
    }

    private static AnnotationProcessingState configureAnnotationProcessing(Args args, SpoonAPI launcher) {
        boolean detectedLombok = detectsLombok(args.projectRoot, args.sourceRoot);
        boolean enabled = "on".equals(args.lombokProcessorMode)
            || ("auto".equals(args.lombokProcessorMode) && detectedLombok);
        AnnotationProcessingState state = new AnnotationProcessingState(
            args.lombokProcessorMode,
            detectedLombok,
            enabled,
            enabled ? LOMBOK_PROCESSOR : "",
            "",
            ""
        );
        if (!enabled) {
            return state;
        }
        launcher.getEnvironment().setNoClasspath(true);
        state.fallbackReason = "lombok_ecj_agent_incompatible; using Spoon no-classpath tolerance with Lombok processor metadata";
        Class<?> processorClass = lombokProcessorClass();
        List<String> classpath = new ArrayList<>();
        String[] envClasspath = launcher.getEnvironment().getSourceClasspath();
        if (envClasspath != null) {
            Collections.addAll(classpath, envClasspath);
        }
        classpath.addAll(args.classpath);
        String processorLocation = classLocation(processorClass);
        state.processorPath = processorLocation;
        if (!processorLocation.isBlank()) {
            classpath.add(processorLocation);
        }
        launcher.getEnvironment().setSourceClasspath(dedupe(classpath).toArray(new String[0]));
        return state;
    }

    private static Class<?> lombokProcessorClass() {
        try {
            return Class.forName(LOMBOK_PROCESSOR);
        } catch (ClassNotFoundException exc) {
            throw new IllegalStateException("Lombok annotation processor is not available: " + LOMBOK_PROCESSOR, exc);
        }
    }

    private static String classLocation(Class<?> clazz) {
        CodeSource codeSource = clazz.getProtectionDomain() == null ? null : clazz.getProtectionDomain().getCodeSource();
        URL location = codeSource == null ? null : codeSource.getLocation();
        if (location == null) {
            return "";
        }
        try {
            return Paths.get(location.toURI()).toAbsolutePath().normalize().toString();
        } catch (Exception ignored) {
            return location.getPath();
        }
    }

    private static void buildModel(MavenLauncher launcher, Args args, AnnotationProcessingState annotationProcessing) {
        if (!annotationProcessing.enabled || !annotationProcessing.fallbackReason.isBlank()) {
            launcher.buildModel();
            return;
        }
        SpoonModelBuilder modelBuilder = launcher.getModelBuilder();
        if (!(modelBuilder instanceof JDTBasedSpoonCompiler compiler)) {
            String reason = "Spoon model builder is not JDTBasedSpoonCompiler: " + modelBuilder.getClass().getName();
            annotationProcessing.fallbackReason = reason;
            throw new IllegalStateException(reason);
        }
        List<String> classpath = new ArrayList<>();
        String[] envClasspath = launcher.getEnvironment().getSourceClasspath();
        if (envClasspath != null) {
            Collections.addAll(classpath, envClasspath);
        }
        List<String> jdtArgs = new ArrayList<>();
        List<String> dedupedClasspath = dedupe(classpath);
        if (!dedupedClasspath.isEmpty()) {
            jdtArgs.add("-cp");
            jdtArgs.add(String.join(File.pathSeparator, dedupedClasspath));
        }
        String processorPath = String.join(File.pathSeparator, dedupedClasspath);
        if (!processorPath.isBlank()) {
            jdtArgs.add("-processorpath");
            jdtArgs.add(processorPath);
        }
        jdtArgs.add(complianceFlag(args.compliance));
        jdtArgs.add("-processor");
        jdtArgs.add(LOMBOK_PROCESSOR);
        jdtArgs.add("-encoding");
        jdtArgs.add("UTF-8");
        jdtArgs.add(args.sourceRoot.toString());
        JDTBuilder builder = new RawJdtBuilder(jdtArgs);
        boolean built = compiler.build(builder);
        if (!built) {
            annotationProcessing.fallbackReason = "Spoon JDT build returned false with Lombok annotation processor";
            throw new IllegalStateException(annotationProcessing.fallbackReason);
        }
    }

    private static boolean detectsLombok(Path projectRoot, Path sourceRoot) {
        return pomUsesLombok(projectRoot.resolve("pom.xml")) || sourceUsesLombok(sourceRoot);
    }

    private static String complianceFlag(int compliance) {
        if (compliance < 10) {
            return "-" + "1." + compliance;
        }
        return "-" + compliance;
    }

    private static boolean pomUsesLombok(Path pom) {
        if (!pom.toFile().exists()) {
            return false;
        }
        try {
            String text = java.nio.file.Files.readString(pom);
            return text.contains("org.projectlombok") || text.contains("<artifactId>lombok</artifactId>");
        } catch (IOException ignored) {
            return false;
        }
    }

    private static boolean sourceUsesLombok(Path sourceRoot) {
        if (!sourceRoot.toFile().exists()) {
            return false;
        }
        try (var paths = java.nio.file.Files.walk(sourceRoot)) {
            return paths
                .filter(path -> path.toString().endsWith(".java"))
                .filter(path -> !isIgnoredSourcePath(sourceRoot, path))
                .anyMatch(SpoonStructureExporter::fileContainsLombokMarker);
        } catch (IOException ignored) {
            return false;
        }
    }

    private static boolean isIgnoredSourcePath(Path sourceRoot, Path path) {
        Path relative;
        try {
            relative = sourceRoot.toAbsolutePath().normalize().relativize(path.toAbsolutePath().normalize());
        } catch (IllegalArgumentException ignored) {
            relative = path;
        }
        for (Path part : relative) {
            String name = part.toString();
            if (
                ".git".equals(name)
                    || "target".equals(name)
                    || "build".equals(name)
                    || ".zscope_knowledge".equals(name)
                    || ".zscope_snapshots".equals(name)
                    || ".zscope_conversations".equals(name)
                    || "node_modules".equals(name)
            ) {
                return true;
            }
        }
        return false;
    }

    private static boolean fileContainsLombokMarker(Path path) {
        try {
            String text = java.nio.file.Files.readString(path);
            for (String marker : LOMBOK_MARKERS) {
                if (text.contains(marker)) {
                    return true;
                }
            }
            return false;
        } catch (IOException ignored) {
            return false;
        }
    }

    private static Map<String, Object> buildMetadata(
        Args args,
        SpoonAPI launcher,
        AnnotationProcessingState annotationProcessing
    ) {
        Map<String, Object> build = new LinkedHashMap<>();
        build.put("project_root", args.projectRoot.toString());
        build.put("source_root", args.sourceRoot.toString());
        build.put("build_tools", Collections.singletonList("maven"));
        List<String> classpath = new ArrayList<>();
        try {
            String[] envClasspath = launcher.getEnvironment().getSourceClasspath();
            if (envClasspath != null) {
                Collections.addAll(classpath, envClasspath);
            }
        } catch (Exception ignored) {
            classpath.addAll(args.classpath);
        }
        build.put("classpath_entries", dedupe(classpath));
        Map<String, Object> maven = new LinkedHashMap<>();
        File pom = args.projectRoot.resolve("pom.xml").toFile();
        if (pom.exists()) {
            maven.put("pom", pom.getAbsolutePath());
            maven.put("source_type", "ALL_SOURCE");
            maven.put("force_refresh", args.forceRefresh);
        }
        build.put("maven", maven);
        Map<String, Object> processing = new LinkedHashMap<>();
        processing.put("enabled", annotationProcessing.enabled);
        processing.put("processor", annotationProcessing.processor);
        processing.put("processor_path", annotationProcessing.processorPath);
        processing.put("detected_lombok", annotationProcessing.detectedLombok);
        processing.put("mode", annotationProcessing.mode);
        processing.put("fallback_reason", annotationProcessing.fallbackReason);
        build.put("annotation_processing", processing);
        return build;
    }

    private static List<Object> exportTypes(CtModel model, Path sourceRoot) {
        List<Object> rows = new ArrayList<>();
        for (CtType<?> type : model.getAllTypes()) {
            if (type == null || type.isShadow()) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            String qualifiedName = emptyToDefault(type.getQualifiedName(), type.getSimpleName());
            row.put("name", type.getSimpleName());
            row.put("fullName", qualifiedName);
            row.put("full_name", qualifiedName);
            row.put("package", type.getPackage() == null ? "" : type.getPackage().getQualifiedName());
            row.put("file", relativeFile(sourceRoot, type));
            row.put("start_line", line(type));
            row.put("end_line", endLine(type));
            row.put("kind", kind(type));
            row.put("annotations", annotations(type.getAnnotations()));
            row.put("fields", fields(type));
            List<Object> methods = new ArrayList<>();
            for (CtConstructor<?> constructor : constructors(type)) {
                methods.add(executable(type, constructor, true, sourceRoot));
            }
            for (CtMethod<?> method : type.getMethods()) {
                methods.add(executable(type, method, false, sourceRoot));
            }
            row.put("methods", methods);
            rows.add(row);
        }
        return rows;
    }

    private static Map<String, Object> executable(
        CtType<?> owner,
        CtExecutable<?> executable,
        boolean constructor,
        Path sourceRoot
    ) {
        Map<String, Object> row = new LinkedHashMap<>();
        String name = constructor ? owner.getSimpleName() : executable.getSimpleName();
        String returnType = constructor ? "void" : typeName(((CtMethod<?>) executable).getType());
        List<Object> params = parameters(executable.getParameters());
        String signature = signature(returnType, executable.getParameters());
        String fullName = owner.getQualifiedName() + "." + name + ":" + signature;
        row.put("name", name);
        row.put("fullName", fullName);
        row.put("qualified_name", fullName);
        row.put("method_full_name", fullName);
        row.put("class_name", owner.getSimpleName());
        row.put("class_full_name", owner.getQualifiedName());
        row.put("package", owner.getPackage() == null ? "" : owner.getPackage().getQualifiedName());
        row.put("file", relativeFile(sourceRoot, executable));
        row.put("filename", relativeFile(sourceRoot, executable));
        row.put("start_line", line(executable));
        row.put("end_line", endLine(executable));
        row.put("lineNumber", line(executable));
        row.put("lineNumberEnd", endLine(executable));
        row.put("signature", signature);
        row.put("code", declarationCode(executable));
        row.put("declaration_code", declarationCode(executable));
        row.put("return_type", returnType);
        row.put("parameters", params);
        row.put("parameterAnnotations", params);
        row.put("annotations", annotations(executable.getAnnotations()));
        row.put("classAnnotations", annotations(owner.getAnnotations()));
        row.put("class_annotations", annotations(owner.getAnnotations()));
        row.put("calls", calls(executable, sourceRoot));
        row.put("is_declaration", executable.getBody() == null);
        row.put("is_public", hasModifier(executable, ModifierKind.PUBLIC));
        row.put("is_static", hasModifier(executable, ModifierKind.STATIC));
        row.put("language", "java");
        row.put("frontend", "spoon");
        row.put("precision", "source_level_exact");
        row.put("structure_precision", "source_level_exact");
        return row;
    }

    private static List<Object> annotations(Collection<CtAnnotation<? extends java.lang.annotation.Annotation>> annotations) {
        List<Object> rows = new ArrayList<>();
        for (CtAnnotation<?> annotation : annotations) {
            Map<String, Object> row = new LinkedHashMap<>();
            String fullName = annotation.getAnnotationType() == null
                ? annotation.toString()
                : annotation.getAnnotationType().getQualifiedName();
            row.put("name", simpleName(fullName));
            row.put("fullName", fullName);
            row.put("code", annotation.toString());
            row.put("lineNumber", line(annotation));
            rows.add(row);
        }
        return rows;
    }

    private static List<CtConstructor<?>> constructors(CtType<?> type) {
        List<CtConstructor<?>> rows = new ArrayList<>();
        for (CtElement member : type.getTypeMembers()) {
            if (member instanceof CtConstructor<?> constructor) {
                rows.add(constructor);
            }
        }
        return rows;
    }

    private static boolean hasModifier(CtElement element, ModifierKind modifier) {
        return element instanceof CtModifiable modifiable && modifiable.getModifiers().contains(modifier);
    }

    private static Map<String, String> fields(CtType<?> type) {
        Map<String, String> rows = new LinkedHashMap<>();
        for (CtField<?> field : type.getFields()) {
            rows.put(field.getSimpleName(), typeName(field.getType()));
        }
        String loggerType = lombokLoggerType(type.getAnnotations());
        if (!loggerType.isBlank() && !rows.containsKey("log")) {
            rows.put("log", loggerType);
        }
        return rows;
    }

    private static String lombokLoggerType(Collection<CtAnnotation<? extends java.lang.annotation.Annotation>> annotations) {
        for (CtAnnotation<?> annotation : annotations) {
            String fullName = annotation.getAnnotationType() == null
                ? annotation.toString()
                : annotation.getAnnotationType().getQualifiedName();
            String name = simpleName(fullName);
            switch (name) {
                case "Slf4j":
                case "XSlf4j":
                    return "org.slf4j.Logger";
                case "Log4j2":
                    return "org.apache.logging.log4j.Logger";
                case "Log":
                    return "java.util.logging.Logger";
                case "CommonsLog":
                    return "org.apache.commons.logging.Log";
                default:
                    break;
            }
        }
        return "";
    }

    private static List<Object> parameters(List<CtParameter<?>> parameters) {
        List<Object> rows = new ArrayList<>();
        for (CtParameter<?> parameter : parameters) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", parameter.getSimpleName());
            row.put("typeFullName", typeName(parameter.getType()));
            row.put("code", parameter.toString());
            row.put("annotations", annotations(parameter.getAnnotations()));
            rows.add(row);
        }
        return rows;
    }

    private static List<Object> calls(CtExecutable<?> executable, Path sourceRoot) {
        List<Object> rows = new ArrayList<>();
        for (CtInvocation<?> invocation : executable.getElements(new TypeFilter<>(CtInvocation.class))) {
            CtExecutableReference<?> ref = invocation.getExecutable();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", ref == null ? "" : ref.getSimpleName());
            row.put("method", ref == null ? "" : ref.getSimpleName());
            row.put("receiver", invocation.getTarget() == null ? "" : invocation.getTarget().toString());
            row.put("code", invocation.toString());
            row.put("line", line(invocation));
            row.put("arguments", invocation.getArguments().stream().map(Object::toString).toList());
            row.put("file", relativeFile(sourceRoot, invocation));
            if (ref != null) {
                row.put("fullName", executableReferenceName(ref));
                row.put("declaring_type", ref.getDeclaringType() == null ? "" : typeName(ref.getDeclaringType()));
                row.put("return_type", typeName(ref.getType()));
                row.put("signature", signature(typeName(ref.getType()), ref.getParameters()));
            }
            row.put("call_type", "spoon_source_structure");
            row.put("confidence", 0.85);
            row.put("precision", "source_level_exact");
            rows.add(row);
        }
        return rows;
    }

    private static String executableReferenceName(CtExecutableReference<?> ref) {
        String declaringType = ref.getDeclaringType() == null ? "" : typeName(ref.getDeclaringType());
        String returnType = typeName(ref.getType());
        String prefix = declaringType.isEmpty() ? ref.getSimpleName() : declaringType + "." + ref.getSimpleName();
        return prefix + ":" + signature(returnType, ref.getParameters());
    }

    private static String signature(String returnType, List<CtParameter<?>> parameters) {
        List<CtTypeReference<?>> types = new ArrayList<>();
        for (CtParameter<?> parameter : parameters) {
            types.add(parameter.getType());
        }
        return signature(returnType, types);
    }

    private static String signature(String returnType, Collection<CtTypeReference<?>> parameters) {
        List<String> parts = new ArrayList<>();
        for (CtTypeReference<?> parameter : parameters) {
            parts.add(typeName(parameter));
        }
        return emptyToDefault(returnType, "void") + "(" + String.join(",", parts) + ")";
    }

    private static String declarationCode(CtExecutable<?> executable) {
        String text = executable.toString();
        int brace = text.indexOf('{');
        if (brace >= 0) {
            text = text.substring(0, brace);
        }
        return text.replace('\n', ' ').replaceAll("\\s+", " ").trim();
    }

    private static String kind(CtType<?> type) {
        if (type.isInterface()) {
            return "interface";
        }
        if (type.isEnum()) {
            return "enum";
        }
        if (type.isAnnotationType()) {
            return "annotation";
        }
        return "class";
    }

    private static String typeName(CtTypeReference<?> ref) {
        if (ref == null) {
            return "";
        }
        try {
            String qualified = ref.getQualifiedName();
            if (qualified != null && !qualified.isBlank()) {
                return qualified;
            }
        } catch (Exception ignored) {
        }
        return ref.toString();
    }

    private static String simpleName(String fullName) {
        int idx = fullName.lastIndexOf('.');
        return idx >= 0 ? fullName.substring(idx + 1) : fullName;
    }

    private static String relativeFile(Path sourceRoot, CtElement element) {
        SourcePosition position = element.getPosition();
        if (position == null || !position.isValidPosition() || position.getFile() == null) {
            return "";
        }
        Path file = position.getFile().toPath().toAbsolutePath().normalize();
        Path root = sourceRoot.toAbsolutePath().normalize();
        try {
            return root.relativize(file).toString().replace(File.separatorChar, '/');
        } catch (IllegalArgumentException ignored) {
            return file.toString().replace(File.separatorChar, '/');
        }
    }

    private static int line(CtElement element) {
        SourcePosition position = element.getPosition();
        return position != null && position.isValidPosition() ? position.getLine() : -1;
    }

    private static int endLine(CtElement element) {
        SourcePosition position = element.getPosition();
        return position != null && position.isValidPosition() ? position.getEndLine() : line(element);
    }

    private static String emptyToDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static List<String> dedupe(Collection<String> items) {
        Set<String> seen = new LinkedHashSet<>();
        for (String item : items) {
            if (item != null && !item.isBlank()) {
                seen.add(item);
            }
        }
        return new ArrayList<>(seen);
    }

    private static final class Args {
        final Path sourceRoot;
        final Path projectRoot;
        final List<String> classpath;
        final boolean forceRefresh;
        final boolean noClasspath;
        final int compliance;
        final String lombokProcessorMode;

        private Args(
            Path sourceRoot,
            Path projectRoot,
            List<String> classpath,
            boolean forceRefresh,
            boolean noClasspath,
            int compliance,
            String lombokProcessorMode
        ) {
            this.sourceRoot = sourceRoot;
            this.projectRoot = projectRoot;
            this.classpath = classpath;
            this.forceRefresh = forceRefresh;
            this.noClasspath = noClasspath;
            this.compliance = compliance;
            this.lombokProcessorMode = lombokProcessorMode;
        }

        static Args parse(String[] rawArgs) {
            Path sourceRoot = Paths.get(".").toAbsolutePath().normalize();
            Path projectRoot = null;
            List<String> classpath = new ArrayList<>();
            boolean forceRefresh = false;
            boolean noClasspath = false;
            int compliance = 17;
            String lombokProcessorMode = "auto";
            for (int idx = 0; idx < rawArgs.length; idx++) {
                String arg = rawArgs[idx];
                switch (arg) {
                    case "--source-root":
                        sourceRoot = Paths.get(require(rawArgs, ++idx, arg)).toAbsolutePath().normalize();
                        break;
                    case "--project-root":
                        projectRoot = Paths.get(require(rawArgs, ++idx, arg)).toAbsolutePath().normalize();
                        break;
                    case "--classpath":
                        classpath.addAll(splitClasspath(require(rawArgs, ++idx, arg)));
                        break;
                    case "--force-refresh":
                        forceRefresh = true;
                        break;
                    case "--no-classpath":
                        noClasspath = true;
                        break;
                    case "--compliance":
                        compliance = Integer.parseInt(require(rawArgs, ++idx, arg));
                        break;
                    case "--lombok-processor":
                        lombokProcessorMode = require(rawArgs, ++idx, arg).toLowerCase(Locale.ROOT);
                        if (
                            !"auto".equals(lombokProcessorMode)
                                && !"off".equals(lombokProcessorMode)
                                && !"on".equals(lombokProcessorMode)
                        ) {
                            throw new IllegalArgumentException(
                                "--lombok-processor must be one of auto, off, on: " + lombokProcessorMode
                            );
                        }
                        break;
                    case "--help":
                    case "-h":
                        usageAndExit();
                        break;
                    default:
                        if (arg.startsWith("--")) {
                            throw new IllegalArgumentException("Unknown argument: " + arg);
                        }
                        sourceRoot = Paths.get(arg).toAbsolutePath().normalize();
                        break;
                }
            }
            if (projectRoot == null) {
                projectRoot = findProjectRoot(sourceRoot);
            }
            return new Args(
                sourceRoot,
                projectRoot,
                classpath,
                forceRefresh,
                noClasspath,
                compliance,
                lombokProcessorMode
            );
        }

        private static List<String> splitClasspath(String raw) {
            if (raw == null || raw.isBlank()) {
                return Collections.emptyList();
            }
            String[] parts = raw.split(java.util.regex.Pattern.quote(File.pathSeparator));
            List<String> result = new ArrayList<>();
            for (String part : parts) {
                if (!part.isBlank()) {
                    result.add(part);
                }
            }
            return result;
        }

        private static Path findProjectRoot(Path sourceRoot) {
            Path cursor = sourceRoot;
            while (cursor != null) {
                if (cursor.resolve("pom.xml").toFile().exists()) {
                    return cursor;
                }
                cursor = cursor.getParent();
            }
            return sourceRoot;
        }

        private static String require(String[] args, int idx, String flag) {
            if (idx >= args.length) {
                throw new IllegalArgumentException(flag + " requires a value");
            }
            return args[idx];
        }

        private static void usageAndExit() {
            System.err.println(
                "Usage: java -jar zscope-java-structure-spoon.jar [options] <source_root>\n"
                    + "  --project-root <path>   Maven project root; auto-detected from source_root by default\n"
                    + "  --source-root <path>    Source root, equivalent to positional source_root\n"
                    + "  --classpath <cp>        Extra classpath separated by " + File.pathSeparator + "\n"
                    + "  --force-refresh         Force MavenLauncher classpath refresh\n"
                    + "  --no-classpath          Enable Spoon no-classpath mode\n"
                    + "  --compliance <level>    Java compliance level, default 17\n"
                    + "  --lombok-processor <auto|off|on>\n"
                    + "                           Enable Lombok annotation processing, default auto"
            );
            System.exit(0);
        }
    }

    private static final class AnnotationProcessingState {
        final String mode;
        final boolean detectedLombok;
        final boolean enabled;
        final String processor;
        String processorPath;
        String fallbackReason;

        private AnnotationProcessingState(
            String mode,
            boolean detectedLombok,
            boolean enabled,
            String processor,
            String processorPath,
            String fallbackReason
        ) {
            this.mode = mode;
            this.detectedLombok = detectedLombok;
            this.enabled = enabled;
            this.processor = processor;
            this.processorPath = processorPath;
            this.fallbackReason = fallbackReason;
        }
    }

    private static final class RawJdtBuilder implements JDTBuilder {
        private final String[] args;

        private RawJdtBuilder(List<String> args) {
            this.args = args.toArray(new String[0]);
        }

        @Override
        public JDTBuilder classpathOptions(spoon.compiler.builder.ClasspathOptions<?> options) {
            return this;
        }

        @Override
        public JDTBuilder complianceOptions(spoon.compiler.builder.ComplianceOptions<?> options) {
            return this;
        }

        @Override
        public JDTBuilder annotationProcessingOptions(spoon.compiler.builder.AnnotationProcessingOptions<?> options) {
            return this;
        }

        @Override
        public JDTBuilder advancedOptions(spoon.compiler.builder.AdvancedOptions<?> options) {
            return this;
        }

        @Override
        public JDTBuilder sources(spoon.compiler.builder.SourceOptions<?> options) {
            return this;
        }

        @Override
        public String[] build() {
            return args;
        }
    }

    private static final class Json {
        private Json() {
        }

        static String write(Object value) {
            StringBuilder out = new StringBuilder();
            append(out, value);
            return out.toString();
        }

        @SuppressWarnings("unchecked")
        private static void append(StringBuilder out, Object value) {
            if (value == null) {
                out.append("null");
            } else if (value instanceof String str) {
                string(out, str);
            } else if (value instanceof Number || value instanceof Boolean) {
                out.append(value.toString());
            } else if (value instanceof Map<?, ?> map) {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    string(out, String.valueOf(entry.getKey()));
                    out.append(':');
                    append(out, entry.getValue());
                }
                out.append('}');
            } else if (value instanceof Iterable<?> iterable) {
                out.append('[');
                boolean first = true;
                for (Object item : iterable) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    append(out, item);
                }
                out.append(']');
            } else {
                string(out, String.valueOf(value));
            }
        }

        private static void string(StringBuilder out, String value) {
            out.append('"');
            for (int idx = 0; idx < value.length(); idx++) {
                char ch = value.charAt(idx);
                switch (ch) {
                    case '"':
                        out.append("\\\"");
                        break;
                    case '\\':
                        out.append("\\\\");
                        break;
                    case '\b':
                        out.append("\\b");
                        break;
                    case '\f':
                        out.append("\\f");
                        break;
                    case '\n':
                        out.append("\\n");
                        break;
                    case '\r':
                        out.append("\\r");
                        break;
                    case '\t':
                        out.append("\\t");
                        break;
                    default:
                        if (ch < 0x20) {
                            out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
                        } else {
                            out.append(ch);
                        }
                }
            }
            out.append('"');
        }
    }
}

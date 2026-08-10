package com.zscope.tools;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.AnnotationDeclaration;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public final class JavaParserStructureExporter {
    private static final Set<String> SKIP_DIRS = Set.of(
        ".git",
        ".gradle",
        ".idea",
        "build",
        "generated",
        "generated-sources",
        "node_modules",
        "out",
        "target"
    );

    private JavaParserStructureExporter() {
    }

    public static void main(String[] rawArgs) throws Exception {
        Args args = Args.parse(rawArgs);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("frontend", "javaparser");
        payload.put("precision", "source_level_approx");
        payload.put("build", buildMetadata(args));
        payload.put("classes", exportClasses(args));
        System.out.println(Json.write(payload));
    }

    private static Map<String, Object> buildMetadata(Args args) {
        Map<String, Object> build = new LinkedHashMap<>();
        build.put("project_root", args.projectRoot.toString());
        build.put("source_root", args.sourceRoot.toString());
        build.put("classpath_entries", dedupe(args.classpath));
        if (args.projectRoot.resolve("pom.xml").toFile().exists()) {
            build.put("build_tools", List.of("maven"));
            build.put("pom", args.projectRoot.resolve("pom.xml").toString());
        } else {
            build.put("build_tools", Collections.emptyList());
        }
        return build;
    }

    private static List<Map<String, Object>> exportClasses(Args args) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Path file : javaFiles(args.sourceRoot)) {
            CompilationUnit unit;
            try {
                unit = StaticJavaParser.parse(file);
            } catch (Exception ignored) {
                continue;
            }
            String packageName = unit.getPackageDeclaration().map(item -> item.getNameAsString()).orElse("");
            for (TypeDeclaration<?> type : unit.findAll(TypeDeclaration.class)) {
                rows.add(exportType(args.sourceRoot, file, packageName, type));
            }
        }
        return rows;
    }

    private static Map<String, Object> exportType(
        Path sourceRoot,
        Path file,
        String packageName,
        TypeDeclaration<?> type
    ) {
        String name = type.getNameAsString();
        String fullName = packageName.isBlank() ? name : packageName + "." + name;
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", name);
        row.put("full_name", fullName);
        row.put("fullName", fullName);
        row.put("package", packageName);
        row.put("file", relativeFile(sourceRoot, file));
        row.put("start_line", line(type));
        row.put("end_line", endLine(type));
        row.put("kind", kind(type));
        row.put("annotations", annotations(type));
        row.put("fields", fields(type));
        row.put("methods", methods(sourceRoot, file, packageName, name, fullName, type));
        return row;
    }

    private static List<Map<String, Object>> methods(
        Path sourceRoot,
        Path file,
        String packageName,
        String className,
        String classFullName,
        TypeDeclaration<?> type
    ) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (BodyDeclaration<?> member : type.getMembers()) {
            if (member instanceof MethodDeclaration method) {
                rows.add(methodRow(sourceRoot, file, packageName, className, classFullName, method));
            } else if (member instanceof ConstructorDeclaration constructor) {
                rows.add(constructorRow(sourceRoot, file, packageName, className, classFullName, constructor));
            }
        }
        return rows;
    }

    private static Map<String, Object> methodRow(
        Path sourceRoot,
        Path file,
        String packageName,
        String className,
        String classFullName,
        MethodDeclaration method
    ) {
        String returnType = method.getType().asString();
        List<Map<String, Object>> parameters = parameters(method.getParameters());
        String signature = signature(returnType, method.getParameters());
        String qualified = classFullName + "." + method.getNameAsString() + ":" + signature;
        Map<String, Object> row = callableBase(
            sourceRoot,
            file,
            packageName,
            className,
            classFullName,
            method.getNameAsString(),
            qualified,
            signature,
            returnType,
            parameters,
            method,
            method.getDeclarationAsString(true, true, true),
            method.getModifiers()
        );
        row.put("calls", calls(method));
        return row;
    }

    private static Map<String, Object> constructorRow(
        Path sourceRoot,
        Path file,
        String packageName,
        String className,
        String classFullName,
        ConstructorDeclaration constructor
    ) {
        List<Map<String, Object>> parameters = parameters(constructor.getParameters());
        String signature = signature("void", constructor.getParameters());
        String qualified = classFullName + "." + constructor.getNameAsString() + ":" + signature;
        Map<String, Object> row = callableBase(
            sourceRoot,
            file,
            packageName,
            className,
            classFullName,
            constructor.getNameAsString(),
            qualified,
            signature,
            "void",
            parameters,
            constructor,
            constructor.getDeclarationAsString(true, true, true),
            constructor.getModifiers()
        );
        row.put("calls", calls(constructor));
        return row;
    }

    private static Map<String, Object> callableBase(
        Path sourceRoot,
        Path file,
        String packageName,
        String className,
        String classFullName,
        String name,
        String qualified,
        String signature,
        String returnType,
        List<Map<String, Object>> parameters,
        NodeWithAnnotations<?> annotated,
        String declaration,
        NodeList<Modifier> modifiers
    ) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", name);
        row.put("qualified_name", qualified);
        row.put("fullName", qualified);
        row.put("class_name", className);
        row.put("class_full_name", classFullName);
        row.put("package", packageName);
        row.put("file", relativeFile(sourceRoot, file));
        row.put("filename", relativeFile(sourceRoot, file));
        row.put("start_line", line((Node) annotated));
        row.put("end_line", endLine((Node) annotated));
        row.put("lineNumber", line((Node) annotated));
        row.put("lineNumberEnd", endLine((Node) annotated));
        row.put("signature", signature);
        row.put("declaration_code", declaration);
        row.put("code", declaration);
        row.put("return_type", returnType);
        row.put("parameters", parameters);
        row.put("parameterAnnotations", parameters);
        row.put("annotations", annotations(annotated));
        row.put("is_public", hasModifier(modifiers, Modifier.Keyword.PUBLIC));
        row.put("is_static", hasModifier(modifiers, Modifier.Keyword.STATIC));
        row.put("is_declaration", false);
        row.put("frontend", "javaparser");
        row.put("precision", "source_level_approx");
        row.put("structure_precision", "source_level_approx");
        return row;
    }

    private static List<Map<String, Object>> calls(Node node) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (MethodCallExpr call : node.findAll(MethodCallExpr.class)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", call.getNameAsString());
            row.put("method", call.getNameAsString());
            row.put("receiver", call.getScope().map(Expression::toString).orElse(""));
            row.put("code", call.toString());
            row.put("line", line(call));
            row.put("arguments", call.getArguments().stream().map(Object::toString).toList());
            rows.add(row);
        }
        return rows;
    }

    private static List<Map<String, Object>> parameters(NodeList<Parameter> parameters) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Parameter parameter : parameters) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", parameter.getNameAsString());
            row.put("typeFullName", parameter.getType().asString());
            row.put("type", parameter.getType().asString());
            row.put("code", parameter.toString());
            row.put("annotations", annotations(parameter));
            rows.add(row);
        }
        return rows;
    }

    private static Map<String, String> fields(TypeDeclaration<?> type) {
        Map<String, String> rows = new LinkedHashMap<>();
        for (FieldDeclaration field : type.findAll(FieldDeclaration.class)) {
            field.getVariables().forEach(variable -> rows.put(variable.getNameAsString(), variable.getType().asString()));
        }
        return rows;
    }

    private static List<Map<String, Object>> annotations(NodeWithAnnotations<?> node) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (AnnotationExpr annotation : node.getAnnotations()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", annotation.getNameAsString());
            row.put("fullName", annotation.getNameAsString());
            row.put("code", annotation.toString());
            row.put("lineNumber", line(annotation));
            row.put("line", line(annotation));
            rows.add(row);
        }
        return rows;
    }

    private static String signature(String returnType, NodeList<Parameter> parameters) {
        List<String> parts = new ArrayList<>();
        for (Parameter parameter : parameters) {
            parts.add(parameter.getType().asString());
        }
        return emptyToDefault(returnType, "void") + "(" + String.join(",", parts) + ")";
    }

    private static boolean hasModifier(NodeList<Modifier> modifiers, Modifier.Keyword keyword) {
        for (Modifier modifier : modifiers) {
            if (modifier.getKeyword() == keyword) {
                return true;
            }
        }
        return false;
    }

    private static String kind(TypeDeclaration<?> type) {
        if (type instanceof ClassOrInterfaceDeclaration item) {
            return item.isInterface() ? "interface" : "class";
        }
        if (type instanceof EnumDeclaration) {
            return "enum";
        }
        if (type instanceof RecordDeclaration) {
            return "record";
        }
        if (type instanceof AnnotationDeclaration) {
            return "annotation";
        }
        return "class";
    }

    private static List<Path> javaFiles(Path sourceRoot) throws Exception {
        List<Path> files = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(sourceRoot)) {
            stream.filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".java"))
                .filter(path -> path.getNameCount() == 0 || path.iterator().hasNext())
                .filter(path -> !hasSkippedPart(path))
                .sorted()
                .forEach(files::add);
        }
        return files;
    }

    private static boolean hasSkippedPart(Path path) {
        for (Path part : path) {
            if (SKIP_DIRS.contains(part.toString())) {
                return true;
            }
        }
        return false;
    }

    private static String relativeFile(Path sourceRoot, Path file) {
        Path root = sourceRoot.toAbsolutePath().normalize();
        Path absoluteFile = file.toAbsolutePath().normalize();
        try {
            return root.relativize(absoluteFile).toString().replace(File.separatorChar, '/');
        } catch (IllegalArgumentException ignored) {
            return absoluteFile.toString().replace(File.separatorChar, '/');
        }
    }

    private static int line(Node node) {
        return node.getRange().map(range -> range.begin.line).orElse(-1);
    }

    private static int endLine(Node node) {
        return node.getRange().map(range -> range.end.line).orElse(line(node));
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

        private Args(Path sourceRoot, Path projectRoot, List<String> classpath) {
            this.sourceRoot = sourceRoot;
            this.projectRoot = projectRoot;
            this.classpath = classpath;
        }

        static Args parse(String[] rawArgs) {
            Path sourceRoot = Paths.get(".").toAbsolutePath().normalize();
            Path projectRoot = null;
            List<String> classpath = new ArrayList<>();
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
            return new Args(sourceRoot, projectRoot, classpath);
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
                "Usage: java -jar zscope-java-structure-javaparser.jar [options] <source_root>\n"
                    + "  --project-root <path>   Build root; auto-detected from source_root by default\n"
                    + "  --source-root <path>    Source root, equivalent to positional source_root\n"
                    + "  --classpath <cp>        Extra classpath separated by " + File.pathSeparator
            );
            System.exit(0);
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

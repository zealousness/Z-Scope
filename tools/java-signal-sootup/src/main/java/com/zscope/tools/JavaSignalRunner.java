package com.zscope.tools;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public final class JavaSignalRunner {
    private static final Set<String> SKIP_DIRS = Set.of(".git", ".gradle", ".idea", "build", "generated", "node_modules", "out", "target");

    private JavaSignalRunner() {
    }

    public static void main(String[] rawArgs) throws Exception {
        Args args = Args.parse(rawArgs);
        List<MethodInfo> methods = collectMethods(args);
        Map<String, String> uniqueBySimpleName = uniqueBySimpleName(methods);
        List<Map<String, Object>> callEdges = new ArrayList<>();
        List<Map<String, Object>> signals = new ArrayList<>();
        for (MethodInfo method : methods) {
            if (!args.entry.isBlank() && !matchesEntry(method.qualifiedName, args.entry)) {
                // Keep provider cost bounded for per-entry invocation while still
                // allowing direct edges out of the requested entry.
                if (!method.qualifiedName.toLowerCase(Locale.ROOT).contains(args.entry.toLowerCase(Locale.ROOT))) {
                    continue;
                }
            }
            collectCallEdges(args, method, uniqueBySimpleName, callEdges);
            collectSignals(args, method, signals);
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("provider", args.provider);
        payload.put("precision", "typed_callgraph_flow");
        payload.put("call_edges", callEdges);
        payload.put("signals", signals);
        payload.put("metadata", Map.of(
            "project_root", args.projectRoot.toString(),
            "source_root", args.sourceRoot.toString(),
            "method_count", methods.size()
        ));
        System.out.println(Json.write(payload));
    }

    private static List<MethodInfo> collectMethods(Args args) throws Exception {
        List<MethodInfo> rows = new ArrayList<>();
        for (Path file : javaFiles(args.sourceRoot)) {
            CompilationUnit unit;
            try {
                unit = StaticJavaParser.parse(file);
            } catch (Exception ignored) {
                continue;
            }
            String packageName = unit.getPackageDeclaration().map(item -> item.getNameAsString()).orElse("");
            for (ClassOrInterfaceDeclaration type : unit.findAll(ClassOrInterfaceDeclaration.class)) {
                String className = type.getNameAsString();
                String classFullName = packageName.isBlank() ? className : packageName + "." + className;
                for (MethodDeclaration method : type.getMethods()) {
                    String signature = method.getType().asString() + "(" + String.join(",", method.getParameters().stream().map(Parameter::getTypeAsString).toList()) + ")";
                    rows.add(new MethodInfo(
                        method.getNameAsString(),
                        classFullName + "." + method.getNameAsString() + ":" + signature,
                        relative(args.sourceRoot, file),
                        line(method),
                        method
                    ));
                }
            }
        }
        rows.sort(Comparator.comparing(item -> item.qualifiedName));
        return rows;
    }

    private static Map<String, String> uniqueBySimpleName(List<MethodInfo> methods) {
        Map<String, String> first = new HashMap<>();
        Set<String> ambiguous = new LinkedHashSet<>();
        for (MethodInfo method : methods) {
            String key = method.simpleName.toLowerCase(Locale.ROOT);
            if (first.containsKey(key)) {
                ambiguous.add(key);
            } else {
                first.put(key, method.qualifiedName);
            }
        }
        for (String key : ambiguous) {
            first.remove(key);
        }
        return first;
    }

    private static void collectCallEdges(Args args, MethodInfo method, Map<String, String> uniqueBySimpleName, List<Map<String, Object>> out) {
        for (MethodCallExpr call : method.node.findAll(MethodCallExpr.class)) {
            String callName = call.getNameAsString();
            String callee = uniqueBySimpleName.getOrDefault(callName.toLowerCase(Locale.ROOT), callName);
            Map<String, Object> edge = new LinkedHashMap<>();
            edge.put("caller", method.qualifiedName);
            edge.put("callee", callee);
            edge.put("call_name", callName);
            edge.put("file", method.file);
            edge.put("line", line(call));
            edge.put("call_type", args.provider + "_call_graph");
            edge.put("confidence", 0.72);
            edge.put("precision", "typed_callgraph_flow");
            out.add(edge);
        }
    }

    private static void collectSignals(Args args, MethodInfo method, List<Map<String, Object>> out) {
        String code = method.node.toString();
        String lowered = code.toLowerCase(Locale.ROOT);
        if (lowered.contains("runtime.getruntime().exec") || lowered.contains("processbuilder")) {
            out.add(signal(args, method, "java_command_execution", "command_injection", "method parameter or derived command", "process execution API", "Runtime.exec or ProcessBuilder"));
        }
        if (lowered.contains("readobject(") || lowered.contains("objectinputstream")) {
            out.add(signal(args, method, "java_object_deserialization", "unsafe_deserialization", "serialized byte stream", "ObjectInputStream.readObject", "Java native deserialization"));
        }
        if (lowered.contains("documentbuilderfactory") || lowered.contains("newdocumentbuilder().parse")) {
            out.add(signal(args, method, "java_xxe_factory", "xxe", "XML string or stream", "DocumentBuilder.parse", "XML parser configuration"));
        }
        if (lowered.contains("executequery(") || lowered.contains("executeupdate(") || lowered.contains("${")) {
            out.add(signal(args, method, "java_sql_execution", "sql_injection", "request parameter or method parameter", "SQL execution or MyBatis text substitution", "SQL sink"));
        }
        if (lowered.contains("openstream(") || lowered.contains("httpclient") || lowered.contains("uri.create")) {
            out.add(signal(args, method, "java_ssrf_http_client", "ssrf", "URL parameter", "outbound HTTP/URL request", "URL client sink"));
        }
        if (lowered.contains("readallbytes(")) {
            out.add(signal(args, method, "java_resource_exhaustion_read_all", "resource_exhaustion", "stream or multipart input", "InputStream.readAllBytes", "unbounded read"));
        }
        if (lowered.contains("hashmap") && lowered.contains(".put(")) {
            out.add(signal(args, method, "java_shared_mutable_static_state", "concurrency_race", "shared static state", "HashMap.put without synchronization", "shared mutable state"));
        }
    }

    private static Map<String, Object> signal(Args args, MethodInfo method, String ruleId, String category, String sourceExpr, String sinkOp, String sinkKind) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("provider", args.provider);
        row.put("rule_id", ruleId);
        row.put("category", category);
        row.put("precision", "typed_callgraph_flow");
        row.put("score", 7.2);
        row.put("source", Map.of(
            "file", method.file,
            "line", method.startLine,
            "function", method.qualifiedName,
            "kind", "java_provider_source",
            "expression", sourceExpr
        ));
        row.put("sink", Map.of(
            "file", method.file,
            "line", method.startLine,
            "function", method.qualifiedName,
            "kind", sinkKind,
            "operation", sinkOp
        ));
        row.put("path", List.of(Map.of(
            "method", method.qualifiedName,
            "file", method.file,
            "line", method.startLine
        )));
        row.put("limitations", List.of(args.provider + " runner emits typed static signal; Z-SCOPE Validator must confirm reachability and guards."));
        return row;
    }

    private static boolean matchesEntry(String method, String entry) {
        String left = method.toLowerCase(Locale.ROOT);
        String right = entry.toLowerCase(Locale.ROOT);
        return left.equals(right) || left.startsWith(right) || right.startsWith(left) || left.contains(right.split(":", 2)[0]);
    }

    private static List<Path> javaFiles(Path root) throws Exception {
        if (!Files.exists(root)) {
            return List.of();
        }
        try (Stream<Path> stream = Files.walk(root)) {
            return stream
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".java"))
                .filter(path -> !isSkippedPath(root, path))
                .toList();
        }
    }

    private static boolean isSkippedPath(Path root, Path path) {
        Path relative;
        try {
            relative = root.toAbsolutePath().normalize().relativize(path.toAbsolutePath().normalize());
        } catch (Exception ignored) {
            relative = path;
        }
        for (Path part : relative) {
            if (SKIP_DIRS.contains(part.toString())) {
                return true;
            }
        }
        return false;
    }

    private static String relative(Path root, Path file) {
        try {
            return root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize()).toString().replace('\\', '/');
        } catch (Exception ignored) {
            return file.toString().replace('\\', '/');
        }
    }

    private static int line(Node node) {
        Optional<com.github.javaparser.Range> range = node.getRange();
        return range.map(value -> value.begin.line).orElse(0);
    }

    private record MethodInfo(String simpleName, String qualifiedName, String file, int startLine, MethodDeclaration node) {
    }

    private static final class Args {
        final Path projectRoot;
        final Path sourceRoot;
        final String entry;
        final String provider;

        private Args(Path projectRoot, Path sourceRoot, String entry, String provider) {
            this.projectRoot = projectRoot;
            this.sourceRoot = sourceRoot;
            this.entry = entry;
            this.provider = provider;
        }

        static Args parse(String[] raw) {
            Map<String, String> values = new HashMap<>();
            for (int i = 0; i < raw.length; i++) {
                String item = raw[i];
                if (!item.startsWith("--")) {
                    continue;
                }
                String key = item.substring(2);
                String value = "true";
                if (i + 1 < raw.length && !raw[i + 1].startsWith("--")) {
                    value = raw[++i];
                }
                values.put(key, value);
            }
            Path projectRoot = Paths.get(values.getOrDefault("project-root", ".")).toAbsolutePath().normalize();
            Path sourceRoot = Paths.get(values.getOrDefault("source-root", projectRoot.toString())).toAbsolutePath().normalize();
            String provider = values.getOrDefault("provider", defaultProvider()).toLowerCase(Locale.ROOT);
            return new Args(projectRoot, sourceRoot, values.getOrDefault("entry", ""), provider);
        }

        private static String defaultProvider() {
            String command = System.getProperty("sun.java.command", "").toLowerCase(Locale.ROOT);
            if (command.contains("wala")) {
                return "wala";
            }
            return "sootup";
        }
    }

    private static final class Json {
        static String write(Object value) {
            StringBuilder out = new StringBuilder();
            append(out, value);
            return out.toString();
        }

        @SuppressWarnings("unchecked")
        private static void append(StringBuilder out, Object value) {
            if (value == null) {
                out.append("null");
            } else if (value instanceof String text) {
                appendString(out, text);
            } else if (value instanceof Number || value instanceof Boolean) {
                out.append(value);
            } else if (value instanceof Map<?, ?> map) {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    appendString(out, String.valueOf(entry.getKey()));
                    out.append(':');
                    append(out, entry.getValue());
                }
                out.append('}');
            } else if (value instanceof Iterable<?> items) {
                out.append('[');
                boolean first = true;
                for (Object item : items) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    append(out, item);
                }
                out.append(']');
            } else {
                appendString(out, String.valueOf(value));
            }
        }

        private static void appendString(StringBuilder out, String value) {
            out.append('"');
            for (int i = 0; i < value.length(); i++) {
                char ch = value.charAt(i);
                switch (ch) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (ch < 0x20) {
                            out.append(String.format("\\u%04x", (int) ch));
                        } else {
                            out.append(ch);
                        }
                    }
                }
            }
            out.append('"');
        }
    }
}

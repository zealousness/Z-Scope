from pathlib import Path

from zscope.core.candidates.java_rules import JavaRuleCandidateGenerator


def _classes(issues):
    return {issue["defect_class"] for issue in issues}


def test_java_rule_generator_detects_high_value_security_sinks() -> None:
    code = """
1 | public void handle(String input) throws Exception {
2 |   Statement st = conn.createStatement();
3 |   st.executeQuery("select * from users where name = '" + input + "'");
4 |   Runtime.getRuntime().exec("sh -c " + input);
5 |   Files.readString(Paths.get(baseDir, input));
6 |   URI uri = URI.create(input);
7 |   new ObjectInputStream(stream).readObject();
8 |   DocumentBuilderFactory.newInstance();
9 |   Cipher.getInstance("AES/ECB/PKCS5Padding");
10 |  new FileInputStream(input);
11 |  new InitialContext().lookup(input);
12 |  dirContext.search(base, "(uid=" + input + ")", controls);
13 |  new SpelExpressionParser().parseExpression(input);
14 |  response.sendRedirect(input);
15 |  ZipInputStream zis = new ZipInputStream(stream);
16 |  new Random().nextInt();
17 |  connection.setHostnameVerifier((host, session) -> true);
18 |  String apiKey = "1234567890abcdef";
19 |  entityManager.createQuery("from User where name = '" + input + "'");
20 |  Document.parse("{\\"name\\":\\"" + input + "\\"}");
21 |  MultipartFile upload = file;
22 |  upload.transferTo(Paths.get(baseDir, upload.getOriginalFilename()));
23 |  JSON.parseObject(input, Object.class);
24 |  freemarkerTemplate.process(model, writer);
25 |  logger.info("token=" + token);
26 |  response.setHeader("X-Name", input);
27 |  response.addCookie(new Cookie("sid", input));
28 |  @CrossOrigin("*")
29 |  http.csrf().disable().authorizeRequests().antMatchers("/**").permitAll();
30 |  IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());
31 |  JWT.decode(input);
32 |  byte[] all = body.readAllBytes();
33 |  Pattern.compile(input);
34 |  Class.forName(input).getMethod("run").invoke(target);
35 |  loader.loadClass(input);
36 |  getResourceAsStream(input);
37 |  File.createTempFile("prefix", ".tmp");
38 |  static HashMap cache = new HashMap();
39 |  userRepository.deleteById(input);
40 |  Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxrwxrwx"));
41 |  XPathFactory.newInstance().newXPath().evaluate("//user[name='" + input + "']", doc);
42 |  ServletRegistrationBean bean = new ServletRegistrationBean(new StatViewServlet(), "/druid/*");
43 |  userMapper.selectUserByUsername(username);
44 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.example.UserController.handle:void(java.lang.String)",
        code,
        "src/main/java/com/example/UserController.java",
    )

    assert {
        "sql_injection",
        "command_injection",
        "path_traversal",
        "ssrf",
        "unsafe_deserialization",
        "xxe",
        "weak_crypto",
        "resource_leak",
        "jndi_injection",
        "ldap_injection",
        "code_injection",
        "open_redirect",
        "weak_random",
        "insecure_tls",
        "secret_exposure",
        "jpa_injection",
        "nosql_injection",
        "file_upload",
        "template_injection",
        "sensitive_log",
        "header_injection",
        "insecure_cookie",
        "cors_misconfiguration",
        "authz_bypass",
        "crypto_misuse",
        "jwt_misuse",
        "resource_exhaustion",
        "regex_dos",
        "reflection_injection",
        "dynamic_class_loading",
        "temp_file_risk",
        "insecure_file_permission",
        "concurrency_race",
        "xpath_injection",
        "sensitive_info_exposure",
        "authz_bypass",
    }.issubset(_classes(issues))
    assert all(issue["candidate_source"] == "java_local_rule" for issue in issues)
    assert all(issue["evidence_pack"]["language"] == "java" for issue in issues)
    assert any(issue["cwe"] == "CWE-89" for issue in issues)


def test_java_rule_generator_detects_javaseclab_high_confidence_rules() -> None:
    code = """
1 | public R jdbc(String username) throws Exception {
2 |   String sql = "SELECT * FROM sqli WHERE username = '" + username + "'";
3 |   PreparedStatement statement = connection.prepareStatement(sql);
4 |   return R.ok(statement.executeQuery());
5 | }
6 | public R xxe(String payload) throws Exception {
7 |   XMLReader xmlReader = XMLReaderFactory.createXMLReader();
8 |   xmlReader.parse(new InputSource(new StringReader(payload)));
9 |   return R.ok();
10 | }
11 | public R xmlDecoder(String payload) {
12 |   new java.beans.XMLDecoder(new ByteArrayInputStream(payload.getBytes())).readObject();
13 |   return R.ok();
14 | }
15 | public String reflected(String payload) {
16 |   return payload;
17 | }
18 | public R stored(String payload, String ua) {
19 |   xssService.insertOne(payload, ua);
20 |   return R.ok();
21 | }
22 | public String template(String payload, Model model) {
23 |   model.addAttribute("html", payload);
24 |   return "vul/xss/other";
25 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "top.whgojp.modules.xss.controller.ReflectController.reflected:java.lang.String(java.lang.String)",
        code,
        "src/main/java/top/whgojp/modules/xss/controller/ReflectController.java",
    )

    by_rule = {issue["rule"]: issue for issue in issues}
    assert {
        "java_jdbc_concatenated_sql",
        "java_jdbc_fake_prepared_statement",
        "java_xxe_factory",
        "java_xmldecoder_readobject",
        "java_reflected_xss_response_body",
        "java_stored_xss_persistent_content",
        "java_template_utext_xss",
    }.issubset(by_rule)
    assert by_rule["java_jdbc_concatenated_sql"]["defect_class"] == "sql_injection"
    assert by_rule["java_xxe_factory"]["evidence_pack"]["path"]["complete_in_function"] is True
    assert by_rule["java_xmldecoder_readobject"]["defect_class"] == "unsafe_deserialization"
    assert by_rule["java_reflected_xss_response_body"]["defect_class"] == "xss"


def test_java_rule_generator_detects_generic_xxe_xss_redirect_config_and_idor() -> None:
    code = """
1 | @ResponseBody
2 | public String reflected(@RequestParam String param) {
3 |   return param;
4 | }
5 | public String redirect(@RequestParam String target, HttpServletResponse response) throws Exception {
6 |   response.sendRedirect(target);
7 |   return "ok";
8 | }
9 | public R druid() {
10 |  return new ServletRegistrationBean(new StatViewServlet(), "/druid/*");
11 | }
12 | public Object user(@RequestParam String username) {
13 |  return userMapper.selectUserByUsername(username);
14 | }
15 | public String xpath(@RequestParam String username) throws Exception {
16 |  return xpath.evaluate("//user[name='" + username + "']", document);
17 | }
18 | public void xxe(String payload) throws Exception {
19 |  SAXParserFactory.newInstance().newSAXParser().parse(new InputSource(new StringReader(payload)), handler);
20 |  DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(payload)));
21 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.example.GenericController.user:java.lang.Object(java.lang.String)",
        code,
        "src/main/java/com/example/GenericController.java",
    )
    by_rule = {issue["rule"]: issue for issue in issues}

    assert by_rule["java_reflected_xss_response_body"]["defect_class"] == "xss"
    assert by_rule["java_open_redirect"]["defect_class"] == "open_redirect"
    assert by_rule["java_druid_monitor_exposure"]["defect_class"] == "sensitive_info_exposure"
    assert by_rule["java_missing_object_authorization"]["defect_class"] == "authz_bypass"
    assert by_rule["java_xpath_expression_concat"]["defect_class"] == "xpath_injection"
    assert by_rule["java_xxe_factory"]["defect_class"] == "xxe"


def test_java_rule_generator_does_not_flag_safe_prepared_statement_as_fake_prepared() -> None:
    code = """
1 | public R safe(String username) throws Exception {
2 |   String sql = "SELECT * FROM sqli WHERE username = ?";
3 |   PreparedStatement statement = connection.prepareStatement(sql);
4 |   statement.setString(1, username);
5 |   return R.ok(statement.executeQuery());
6 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "top.whgojp.modules.sqli.controller.JdbcController.safe:top.whgojp.common.R(java.lang.String)",
        code,
        "src/main/java/top/whgojp/modules/sqli/controller/JdbcController.java",
    )

    assert "java_jdbc_fake_prepared_statement" not in {issue["rule"] for issue in issues}


def test_java_rule_generator_detects_insecure_file_permissions() -> None:
    code = """
1 | public void makeShared(Path path) throws Exception {
2 |   path.toFile().setReadable(true, false);
3 |   path.toFile().setWritable(true, false);
4 |   Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxrwxrwx"));
5 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.example.PermissionTool.makeShared:void(java.nio.file.Path)",
        code,
        "src/main/java/com/example/PermissionTool.java",
    )

    permission = [issue for issue in issues if issue["defect_class"] == "insecure_file_permission"]
    assert permission
    assert all(issue["rule"] == "java_insecure_file_permissions" for issue in permission)
    assert permission[0]["cwe"] == "CWE-732"
    assert permission[0]["evidence_pack"]["path"]["complete_in_function"] is True


def test_java_rule_generator_detects_mybatis_dollar_substitution() -> None:
    code = '1 | @Select("select * from users order by ${sort}")\n2 | User find(String sort);'

    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.example.UserMapper.find:User(java.lang.String)",
        code,
        "src/main/java/com/example/UserMapper.java",
    )

    assert len(issues) == 1
    assert issues[0]["defect_class"] == "sql_injection"
    assert issues[0]["rule"] == "java_mybatis_dollar_substitution"


def test_java_rule_generator_detects_properties_secret_and_authz_state_change() -> None:
    issues = JavaRuleCandidateGenerator().generate_issues(
        "<project-file>:src/main/resources/application.properties",
        "1 | external.service.token=1234567890abcdef\n"
        "2 | admin.password: hunter2-secret\n"
        "3 | userRepository.deleteById(userId);",
        "src/main/resources/application.properties",
    )

    classes = _classes(issues)
    assert "secret_exposure" in classes
    assert "authz_bypass" in classes
    secret = next(issue for issue in issues if issue["defect_class"] == "secret_exposure")
    assert secret["cwe"] == "CWE-798"
    assert secret["evidence_pack"]["path"]["complete_in_function"] is True


def test_java_rule_generator_detects_unconditional_jwt_filter_chain() -> None:
    code = """
1 | public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
2 |   HttpServletRequest httpRequest = (HttpServletRequest) request;
3 |   String token = httpRequest.getHeader("Authorization");
4 |   if (token != null && token.startsWith("Bearer ")) {
5 |     jwtService.decodeWithoutVerification(token.substring(7));
6 |   }
7 |   chain.doFilter(request, response);
8 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.zscope.web.filter.JwtBypassFilter.doFilter:void(jakarta.servlet.ServletRequest,jakarta.servlet.ServletResponse,jakarta.servlet.FilterChain)",
        code,
        "src/main/java/com/zscope/web/filter/JwtBypassFilter.java",
    )

    filter_issue = next(
        issue for issue in issues if issue["rule"] == "java_filter_unconditional_chain"
    )
    assert filter_issue["defect_class"] == "authz_bypass"
    assert filter_issue["cwe"] == "CWE-862"
    assert filter_issue["evidence_pack"]["path"]["complete_in_function"] is True
    assert (
        filter_issue["evidence_pack"]["source"]["kind"]
        == "java_servlet_filter_authentication_boundary"
    )
    assert filter_issue["evidence_pack"]["sink"]["kind"] == "java_servlet_filter_chain_continuation"


def test_java_rule_generator_detects_benchmark_regression_rules_with_structured_evidence() -> None:
    code = """
1 | @CrossOrigin("*")
2 | public String cors(String name) { return name; }
3 | public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
4 |   return http.csrf().disable().authorizeHttpRequests(auth -> auth.requestMatchers("/**").permitAll()).build();
5 | }
6 | public InputStream resource(String name) {
7 |   return getClass().getResourceAsStream(name);
8 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.zscope.BenchmarkSurface.audit:void(java.lang.String)",
        code,
        "src/main/java/com/zscope/BenchmarkSurface.java",
    )
    by_rule = {issue["rule"]: issue for issue in issues}

    assert by_rule["java_cors_wildcard"]["defect_class"] == "cors_misconfiguration"
    assert by_rule["java_cors_wildcard"]["evidence_pack"]["sink"]["kind"] == "java_cors_policy"
    assert by_rule["java_spring_security_permit_all"]["defect_class"] == "authz_bypass"
    assert (
        by_rule["java_spring_security_permit_all"]["evidence_pack"]["sink"]["kind"]
        == "java_spring_security_permit_all"
    )
    assert by_rule["java_classpath_resource_traversal"]["defect_class"] == "path_traversal"
    assert (
        by_rule["java_classpath_resource_traversal"]["evidence_pack"]["path"][
            "complete_in_function"
        ]
        is True
    )


def test_java_rule_generator_does_not_treat_spring_configuration_as_template_engine() -> None:
    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.zscope.web.config.InsecureSecurityConfig.securityFilterChain:org.springframework.security.web.SecurityFilterChain()",
        "1 | @Configuration\n2 | public class InsecureSecurityConfig {}",
        "src/main/java/com/zscope/web/config/InsecureSecurityConfig.java",
    )

    assert all(issue["rule"] != "java_template_injection" for issue in issues)


def test_java_rule_generator_scans_structured_method_annotations() -> None:
    issues = JavaRuleCandidateGenerator().generate_issues(
        "com.example.UserMapper.findBySort:java.lang.Object(java.lang.String)",
        "7 | Object findBySort(String sort);",
        "src/main/java/com/example/UserMapper.java",
        annotations=[
            {
                "name": "Select",
                "fullName": "org.apache.ibatis.annotations.Select",
                "code": '@Select("select * from users order by ${sort}")',
                "lineNumber": 6,
            }
        ],
    )

    assert len(issues) == 1
    assert issues[0]["rule"] == "java_mybatis_dollar_substitution"
    assert issues[0]["location"].endswith("UserMapper.java:6")
    assert '@Select("select * from users order by ${sort}")' in issues[0]["code_snippet"]


def test_java_rule_generator_respects_allowed_skills() -> None:
    code = """
1 | public void handle(String input) throws Exception {
2 |   Runtime.getRuntime().exec(input);
3 |   Cipher.getInstance("DES/ECB/PKCS5Padding");
4 | }
"""

    issues = JavaRuleCandidateGenerator().generate_issues(
        "demo.App.handle:void(java.lang.String)",
        code,
        "src/main/java/demo/App.java",
        allowed_skills=["java_crypto"],
    )

    assert _classes(issues) == {"weak_crypto"}


def test_java_rule_candidate_ticket_uses_java_skill() -> None:
    generator = JavaRuleCandidateGenerator()
    issue = generator.generate_issues(
        "demo.App.handle:void(java.lang.String)",
        "1 | Runtime.getRuntime().exec(input);",
        "src/main/java/demo/App.java",
    )[0]

    ticket = generator.issue_to_ticket(issue)

    assert ticket.skill == "java_injection"
    assert ticket.source == "java_local_rule"
    assert ticket.resource_kind == "process"


def test_java_range_fixture_has_one_candidate_for_every_java_rule() -> None:
    root = Path(__file__).resolve().parents[1] / "test" / "java_range"
    generator = JavaRuleCandidateGenerator()
    seen = set()

    for path in (root / "src" / "main" / "java").rglob("*.java"):
        relative = path.relative_to(root).as_posix()
        numbered_source = "\n".join(
            f"{line_number} | {line}"
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            )
        )
        for issue in generator.generate_issues(
            f"<project-file>:{relative}",
            numbered_source,
            relative,
        ):
            seen.add(issue["rule"])

    assert seen == {rule.rule_id for rule in JavaRuleCandidateGenerator._RULES}

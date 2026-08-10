from zscope.semantics.java_frameworks import (
    build_java_framework_semantics,
    java_framework_summary,
)


def test_builds_spring_entry_and_request_sources() -> None:
    semantics = build_java_framework_semantics(
        {
            "annotations": [
                {
                    "name": "GetMapping",
                    "code": '@GetMapping("/search")',
                    "lineNumber": 12,
                }
            ],
            "class_annotations": [
                {"name": "RestController", "code": "@RestController", "lineNumber": 8},
                {
                    "name": "RequestMapping",
                    "code": '@RequestMapping("/users")',
                    "lineNumber": 9,
                },
            ],
            "parameter_annotations": [
                {
                    "name": "name",
                    "typeFullName": "java.lang.String",
                    "annotations": [
                        {
                            "name": "RequestParam",
                            "code": '@RequestParam("name")',
                            "lineNumber": 13,
                        }
                    ],
                }
            ],
        }
    )

    assert semantics["frameworks"] == ["spring_mvc"]
    assert semantics["entry"]["is_entry"] is True
    assert semantics["entry"]["http_methods"] == ["GET"]
    assert semantics["entry"]["paths"] == ["/users/search"]
    assert semantics["sources"][0]["kind"] == "http_request_param"
    assert semantics["sources"][0]["parameter"] == "name"
    assert semantics["runtime_ir"]["schema"] == "java_framework_runtime_ir.v1"
    assert semantics["runtime_ir"]["entrypoints"][0]["path"] == "/users/search"
    assert semantics["runtime_ir"]["sources"][0]["parameter"] == "name"
    assert "Spring MVC entry" in java_framework_summary(semantics)


def test_builds_mybatis_sql_template_semantics() -> None:
    semantics = build_java_framework_semantics(
        {
            "annotations": [
                {
                    "name": "Select",
                    "code": '@Select("<script>select * from users <if test=\\"sort != null\\">order by ${sort}</if> where id = #{id}</script>")',
                    "lineNumber": 6,
                }
            ]
        }
    )

    assert semantics["frameworks"] == ["mybatis"]
    template = semantics["sql_templates"][0]
    assert template["uses_text_substitution"] is True
    assert template["text_substitution_variables"] == ["sort"]
    assert template["parameter_binding_variables"] == ["id"]
    assert template["dynamic_sql_tags"] == ["if"]
    sink = semantics["runtime_ir"]["sinks"][0]
    assert sink["kind"] == "mybatis_sql_template"
    assert sink["dynamic_sql_tags"] == ["if"]
    assert "MyBatis text substitution" in java_framework_summary(semantics)


def test_builds_extended_java_framework_semantics() -> None:
    semantics = build_java_framework_semantics(
        {
            "name": "handle",
            "signature": "reactor.core.publisher.Mono(java.lang.String)",
            "code": "Mono<ServerResponse> handle(ServerRequest request)",
            "annotations": [
                {"name": "KafkaListener", "code": '@KafkaListener(topics = "orders")'},
                {"name": "Scheduled", "code": '@Scheduled(cron = "* * * * * *")'},
                {"name": "PreAuthorize", "code": "@PreAuthorize(\"hasRole('ADMIN')\")"},
                {"name": "Query", "code": '@Query("select u from User u where u.name = :name")'},
                {"name": "GetMapping", "code": '@GetMapping("/reactive")'},
            ],
            "class_annotations": [
                {"name": "RestController", "code": "@RestController"},
                {"name": "GrpcService", "code": "@GrpcService"},
                {"name": "WebFilter", "code": "@WebFilter"},
            ],
            "parameter_annotations": [
                {
                    "name": "payload",
                    "typeFullName": "java.lang.String",
                    "annotations": [
                        {"name": "Payload", "code": "@Payload"},
                    ],
                }
            ],
        }
    )

    assert "messaging" in semantics["frameworks"]
    assert "scheduled" in semantics["frameworks"]
    assert "spring_security" in semantics["frameworks"]
    assert "spring_data_jpa" in semantics["frameworks"]
    assert "spring_webflux" in semantics["frameworks"]
    assert "servlet_filter" in semantics["frameworks"]
    assert "rpc" in semantics["frameworks"]
    assert semantics["messaging"]["is_consumer"] is True
    assert semantics["scheduled"]["is_scheduled"] is True
    assert semantics["security"]["requires_authz_review"] is True
    assert semantics["data_access"]["queries"][0]["query"].startswith("select u")
    assert semantics["reactive"]["reactive_types"]
    assert semantics["filter_interceptor"]["is_filter"] is True
    assert semantics["rpc"]["is_rpc"] is True
    summary = java_framework_summary(semantics)
    assert "message consumer" in summary
    assert "Spring Security" in summary
    assert "Spring Data JPA" in summary


def test_builds_runtime_java_framework_semantics_without_annotations() -> None:
    semantics = build_java_framework_semantics(
        {
            "name": "configure",
            "signature": "reactor.core.publisher.Mono(java.lang.String)",
            "code": "\n".join(
                [
                    "SecurityFilterChain chain = http.csrf().disable()",
                    '  .authorizeHttpRequests().requestMatchers("/**").permitAll().and().build();',
                    "EntityManager entityManager = factory.createEntityManager();",
                    "entityManager.createQuery(query);",
                    "WebClient.create().get().uri(target).retrieve().bodyToMono(String.class).block();",
                    "new FilterRegistrationBean<>();",
                    "KafkaTemplate<String, String> kafkaTemplate = null;",
                    "kafkaTemplate.send(topic, payload);",
                    "TaskScheduler scheduler = null;",
                    "scheduler.schedule(task, trigger);",
                    "ManagedChannelBuilder.forAddress(host, port);",
                    "StreamObserver<Request> observer = null;",
                ]
            ),
        }
    )

    assert "spring_security" in semantics["frameworks"]
    assert "spring_data_jpa" in semantics["frameworks"]
    assert "spring_webflux" in semantics["frameworks"]
    assert "servlet_filter" in semantics["frameworks"]
    assert "messaging" in semantics["frameworks"]
    assert "scheduled" in semantics["frameworks"]
    assert "rpc" in semantics["frameworks"]

    assert _signal_names(semantics["security"]) >= {"csrf_disabled", "permit_all"}
    assert "entity_manager" in _signal_names(semantics["data_access"])
    assert _signal_names(semantics["reactive"]) >= {
        "webclient_uri",
        "body_to_mono",
        "reactor_block",
    }
    assert "filter_registration" in _signal_names(semantics["filter_interceptor"])
    assert "kafka_template" in _signal_names(semantics["messaging"])
    assert "task_scheduler" in _signal_names(semantics["scheduled"])
    assert _signal_names(semantics["rpc"]) >= {"grpc_channel", "grpc_stream_observer"}
    assert semantics["security"]["policies"]
    assert any(
        policy["decision"] == "permit_all"
        for policy in semantics["runtime_ir"]["security_policies"]
    )
    assert any(
        policy["decision"] == "csrf_disabled"
        for policy in semantics["runtime_ir"]["security_policies"]
    )
    assert any(item["section"] == "security" for item in semantics["runtime_ir"]["runtime_configs"])
    assert any(item["kind"] == "webclient_uri" for item in semantics["runtime_ir"]["sinks"])
    assert any(
        op["operator"] == "bodyToMono" for op in semantics["runtime_ir"]["reactive_pipeline"]
    )
    summary = java_framework_summary(semantics)
    assert "Spring Security runtime signals" in summary
    assert "Spring Data/JPA runtime signals" in summary
    assert "messaging runtime signals" in summary
    assert "grpc_channel" in summary
    assert "runtime security policies" in summary


def test_runtime_ir_extracts_bean_bindings_and_call_edges() -> None:
    semantics = build_java_framework_semantics(
        {
            "name": "search",
            "qualified_name": "demo.UserController.search",
            "code": "\n".join(
                [
                    "@Autowired",
                    "private final UserService userService;",
                    '@Qualifier("primaryMapper")',
                    "private UserMapper userMapper;",
                    "public UserController(UserService userService) {",
                    "  this.userService = userService;",
                    "}",
                    "public Object search(String sort) {",
                    "  return userService.list(sort);",
                    "}",
                ]
            ),
        }
    )

    ir = semantics["runtime_ir"]
    assert any(binding["field"] == "userService" for binding in ir["bindings"])
    assert any(binding.get("bean_name") == "primaryMapper" for binding in ir["bindings"])
    assert any(
        edge["target"] == "userService" and edge["callee"] == "list"
        for edge in ir["propagation_edges"]
    )


def _signal_names(section):
    return {signal["name"] for signal in section.get("runtime_signals", [])}

"""Java framework semantic extraction helpers.

The Joern Java frontend already gives us annotations, parameters, and method
metadata. This module turns those raw CPG rows into a compact semantic layer
that the analyzer, local rules, and CPG rule engine can share.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

SPRING_CONTROLLER_ANNOTATIONS = {
    "Controller",
    "RestController",
}
SPRING_MAPPING_ANNOTATIONS = {
    "RequestMapping": "",
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "PatchMapping": "PATCH",
    "DeleteMapping": "DELETE",
}
SPRING_SOURCE_ANNOTATIONS = {
    "RequestParam": "http_request_param",
    "PathVariable": "http_path_variable",
    "RequestBody": "http_request_body",
    "RequestHeader": "http_header",
    "CookieValue": "http_cookie",
    "ModelAttribute": "http_model_attribute",
    "RequestPart": "http_multipart_part",
    "MatrixVariable": "http_matrix_variable",
}
MYBATIS_SQL_ANNOTATIONS = {
    "Select",
    "Insert",
    "Update",
    "Delete",
    "SelectProvider",
    "InsertProvider",
    "UpdateProvider",
    "DeleteProvider",
}
SPRING_SECURITY_ANNOTATIONS = {
    "EnableWebSecurity",
    "PreAuthorize",
    "PostAuthorize",
    "Secured",
    "RolesAllowed",
    "PermitAll",
    "DenyAll",
    "AuthenticationPrincipal",
}
SPRING_DATA_ANNOTATIONS = {
    "Repository",
    "Entity",
    "Table",
    "Query",
    "Modifying",
    "Transactional",
}
WEBFLUX_ANNOTATIONS = {
    "Controller",
    "RestController",
    "RequestMapping",
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "PatchMapping",
    "DeleteMapping",
}
FILTER_INTERCEPTOR_ANNOTATIONS = {
    "WebFilter",
    "WebListener",
    "Component",
}
MESSAGING_ANNOTATIONS = {
    "KafkaListener",
    "RabbitListener",
    "JmsListener",
    "MessageMapping",
    "Payload",
    "Header",
    "Headers",
    "SendTo",
}
SCHEDULED_ANNOTATIONS = {
    "Scheduled",
    "Async",
}
RPC_ANNOTATIONS = {
    "GrpcService",
    "RpcService",
    "DubboService",
    "DubboReference",
    "FeignClient",
    "ThriftService",
}


def build_java_framework_semantics(method: Dict[str, Any]) -> Dict[str, Any]:
    """Return normalized Java framework facts for one method metadata record."""
    annotations = _annotation_list(method.get("annotations"))
    class_annotations = _annotation_list(
        method.get("class_annotations") or method.get("classAnnotations")
    )
    parameters = _parameter_list(
        method.get("parameter_annotations") or method.get("parameterAnnotations")
    )

    entry = _spring_entry_semantics(annotations, class_annotations)
    sources = _spring_source_semantics(parameters)
    sql_templates = _mybatis_sql_templates(annotations)
    security = _spring_security_semantics(method, annotations, class_annotations, parameters)
    data_access = _spring_data_semantics(method, annotations, class_annotations)
    reactive = _webflux_semantics(
        method, annotations, class_annotations, parameters, entry, sources
    )
    filter_interceptor = _filter_interceptor_semantics(method, annotations, class_annotations)
    messaging = _messaging_semantics(method, annotations, class_annotations, parameters)
    scheduled = _scheduled_semantics(method, annotations, class_annotations)
    rpc = _rpc_semantics(method, annotations, class_annotations)
    runtime_ir = _framework_runtime_ir(
        method,
        entry,
        sources,
        sql_templates,
        security,
        data_access,
        reactive,
        filter_interceptor,
        messaging,
        scheduled,
        rpc,
    )
    frameworks = sorted(
        {
            *("spring_mvc" for _ in [1] if entry.get("is_entry") or sources),
            *("mybatis" for _ in [1] if sql_templates),
            *(
                "spring_security"
                for _ in [1]
                if security.get("annotations") or security.get("runtime_signals")
            ),
            *(
                "spring_data_jpa"
                for _ in [1]
                if data_access.get("annotations")
                or data_access.get("queries")
                or data_access.get("runtime_signals")
            ),
            *("spring_webflux" for _ in [1] if reactive.get("is_reactive")),
            *("servlet_filter" for _ in [1] if filter_interceptor.get("is_filter")),
            *("spring_interceptor" for _ in [1] if filter_interceptor.get("is_interceptor")),
            *("messaging" for _ in [1] if messaging.get("framework")),
            *("scheduled" for _ in [1] if scheduled.get("is_scheduled")),
            *("rpc" for _ in [1] if rpc.get("is_rpc")),
        }
    )

    result: Dict[str, Any] = {
        "frameworks": frameworks,
        "entry": entry,
        "sources": sources,
        "sql_templates": sql_templates,
        "security": security,
        "data_access": data_access,
        "reactive": reactive,
        "filter_interceptor": filter_interceptor,
        "messaging": messaging,
        "scheduled": scheduled,
        "rpc": rpc,
        "runtime_ir": runtime_ir,
    }
    result["has_framework_entry"] = bool(
        entry.get("is_entry")
        or messaging.get("is_consumer")
        or scheduled.get("is_scheduled")
        or rpc.get("is_rpc")
        or filter_interceptor.get("is_filter")
        or filter_interceptor.get("is_interceptor")
    )
    result["has_external_input"] = bool(sources or messaging.get("sources") or rpc.get("sources"))
    return result


def java_framework_summary(semantics: Dict[str, Any]) -> str:
    """Compact human-readable summary for prompts and evidence packs."""
    if not isinstance(semantics, dict):
        return ""
    parts: List[str] = []
    entry = semantics.get("entry") if isinstance(semantics.get("entry"), dict) else {}
    if entry.get("is_entry"):
        methods = ", ".join(entry.get("http_methods") or ["ANY"])
        paths = ", ".join(entry.get("paths") or [])
        parts.append(f"Spring MVC entry {methods} {paths}".strip())
    sources = semantics.get("sources") if isinstance(semantics.get("sources"), list) else []
    if sources:
        names = ", ".join(
            f"{src.get('parameter')}:{src.get('kind')}" for src in sources if isinstance(src, dict)
        )
        parts.append(f"external inputs [{names}]")
    sql_templates = (
        semantics.get("sql_templates") if isinstance(semantics.get("sql_templates"), list) else []
    )
    dollar_templates = [
        item
        for item in sql_templates
        if isinstance(item, dict) and item.get("uses_text_substitution")
    ]
    if dollar_templates:
        vars_text = ", ".join(
            ",".join(item.get("text_substitution_variables") or [])
            for item in dollar_templates
            if isinstance(item, dict)
        )
        parts.append(f"MyBatis text substitution [{vars_text}]")
    security = semantics.get("security") if isinstance(semantics.get("security"), dict) else {}
    if security.get("annotations"):
        parts.append(
            f"Spring Security annotations [{', '.join(security.get('annotations') or [])}]"
        )
    security_runtime = _runtime_signal_names(security)
    if security_runtime:
        parts.append(f"Spring Security runtime signals [{', '.join(security_runtime)}]")
    data_access = (
        semantics.get("data_access") if isinstance(semantics.get("data_access"), dict) else {}
    )
    if data_access.get("queries"):
        parts.append("Spring Data JPA query method")
    data_runtime = _runtime_signal_names(data_access)
    if data_runtime:
        parts.append(f"Spring Data/JPA runtime signals [{', '.join(data_runtime)}]")
    reactive = semantics.get("reactive") if isinstance(semantics.get("reactive"), dict) else {}
    if reactive.get("is_reactive"):
        parts.append("Spring WebFlux/reactive handler")
    filter_interceptor = (
        semantics.get("filter_interceptor")
        if isinstance(semantics.get("filter_interceptor"), dict)
        else {}
    )
    if filter_interceptor.get("is_filter") or filter_interceptor.get("is_interceptor"):
        parts.append("Servlet filter/interceptor boundary")
    messaging = semantics.get("messaging") if isinstance(semantics.get("messaging"), dict) else {}
    if messaging.get("is_consumer"):
        parts.append(f"message consumer [{', '.join(messaging.get('annotations') or [])}]")
    elif messaging.get("runtime_signals"):
        parts.append(f"messaging runtime signals [{', '.join(_runtime_signal_names(messaging))}]")
    scheduled = semantics.get("scheduled") if isinstance(semantics.get("scheduled"), dict) else {}
    if scheduled.get("is_scheduled"):
        parts.append("scheduled job")
    rpc = semantics.get("rpc") if isinstance(semantics.get("rpc"), dict) else {}
    if rpc.get("is_rpc"):
        rpc_labels = list(rpc.get("annotations") or []) + _runtime_signal_names(rpc)
        parts.append(f"RPC endpoint/client [{', '.join(rpc_labels)}]")
    runtime_ir = (
        semantics.get("runtime_ir") if isinstance(semantics.get("runtime_ir"), dict) else {}
    )
    if runtime_ir.get("security_policies"):
        policy_names = ", ".join(
            str(policy.get("decision") or policy.get("kind") or "")
            for policy in runtime_ir.get("security_policies", [])
            if isinstance(policy, dict)
        )
        parts.append(f"runtime security policies [{policy_names}]")
    return "; ".join(part for part in parts if part)


def _spring_entry_semantics(
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    class_mapping_paths: List[str] = []
    class_is_controller = False
    for annotation in class_annotations:
        name = _annotation_name(annotation)
        if name in SPRING_CONTROLLER_ANNOTATIONS:
            class_is_controller = True
        if name == "RequestMapping":
            class_mapping_paths.extend(_annotation_paths(annotation))

    method_paths: List[str] = []
    http_methods: List[str] = []
    mapping_annotations: List[str] = []
    for annotation in annotations:
        name = _annotation_name(annotation)
        if name not in SPRING_MAPPING_ANNOTATIONS:
            continue
        mapping_annotations.append(name)
        method_paths.extend(_annotation_paths(annotation))
        method = SPRING_MAPPING_ANNOTATIONS[name]
        if method:
            http_methods.append(method)
        else:
            http_methods.extend(_annotation_http_methods(annotation))

    is_entry = bool(mapping_annotations and class_is_controller)
    paths = _join_paths(class_mapping_paths or [""], method_paths or [""])
    return {
        "framework": "spring_mvc" if is_entry else "",
        "is_entry": is_entry,
        "controller": class_is_controller,
        "annotations": mapping_annotations,
        "class_paths": class_mapping_paths,
        "method_paths": method_paths,
        "paths": paths,
        "http_methods": sorted(
            dict.fromkeys(http_methods or (["ANY"] if mapping_annotations else []))
        ),
    }


def _spring_source_semantics(parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sources: List[Dict[str, Any]] = []
    for parameter in parameters:
        parameter_name = str(parameter.get("name") or "").strip()
        type_name = str(parameter.get("typeFullName") or parameter.get("type") or "").strip()
        for annotation in _annotation_list(parameter.get("annotations")):
            annotation_name = _annotation_name(annotation)
            kind = SPRING_SOURCE_ANNOTATIONS.get(annotation_name)
            if not kind:
                continue
            external_name = _annotation_named_value(annotation) or parameter_name
            sources.append(
                {
                    "framework": "spring_mvc",
                    "kind": kind,
                    "annotation": annotation_name,
                    "parameter": parameter_name,
                    "external_name": external_name,
                    "type": type_name,
                    "line": _line_number(annotation),
                    "source_expression": parameter_name or external_name,
                    "attacker_control": "external_http_request",
                }
            )
    return sources


def _mybatis_sql_templates(annotations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    templates: List[Dict[str, Any]] = []
    for annotation in annotations:
        name = _annotation_name(annotation)
        if name not in MYBATIS_SQL_ANNOTATIONS:
            continue
        code = str(annotation.get("code") or "")
        sql = _annotation_string_literal(code)
        variables = re.findall(r"\$\{\s*([^}\s]+)\s*}", sql or code)
        bound_variables = re.findall(r"#\{\s*([^}\s]+)\s*}", sql or code)
        dynamic_tags = _mybatis_dynamic_tags(sql or code)
        templates.append(
            {
                "framework": "mybatis",
                "annotation": name,
                "line": _line_number(annotation),
                "code": code,
                "sql": sql,
                "uses_text_substitution": bool(variables),
                "text_substitution_variables": variables,
                "parameter_binding_variables": bound_variables,
                "dynamic_sql_tags": dynamic_tags,
                "uses_dynamic_sql": bool(dynamic_tags),
            }
        )
    return templates


def _spring_security_semantics(
    method: Dict[str, Any],
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
    parameters: List[Dict[str, Any]],
) -> Dict[str, Any]:
    names = _matching_annotation_names(
        [*annotations, *class_annotations], SPRING_SECURITY_ANNOTATIONS
    )
    runtime_signals = _runtime_signal_matches(
        str(method.get("code") or ""),
        {
            "csrf_disabled": r"\bcsrf\s*\(\s*\)\.disable\s*\(",
            "permit_all": r"\bpermitAll\s*\(",
            "security_filter_chain": r"\bSecurityFilterChain\b",
            "authorize_requests": r"\b(?:authorizeRequests|authorizeHttpRequests)\s*\(",
            "request_matchers": r"\b(?:antMatchers|requestMatchers|mvcMatchers)\s*\(",
            "web_ignoring": r"\bweb\.ignoring\s*\(",
        },
    )
    policies = _spring_security_policy_graph(str(method.get("code") or ""), names)
    parameter_sources: List[Dict[str, Any]] = []
    for parameter in parameters:
        for annotation in _annotation_list(parameter.get("annotations")):
            name = _annotation_name(annotation)
            if name in SPRING_SECURITY_ANNOTATIONS:
                parameter_sources.append(
                    {
                        "parameter": str(parameter.get("name") or ""),
                        "annotation": name,
                        "kind": "security_principal",
                        "line": _line_number(annotation),
                    }
                )
    return {
        "framework": "spring_security" if names or parameter_sources or runtime_signals else "",
        "annotations": names,
        "runtime_signals": runtime_signals,
        "policies": policies,
        "principal_sources": parameter_sources,
        "requires_authz_review": any(
            name in {"PermitAll", "PreAuthorize", "Secured", "RolesAllowed"} for name in names
        )
        or any(
            signal["name"] in {"csrf_disabled", "permit_all", "web_ignoring"}
            for signal in runtime_signals
        )
        or any(policy.get("decision") in {"permit_all", "web_ignored"} for policy in policies),
    }


def _spring_data_semantics(
    method: Dict[str, Any],
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    names = _matching_annotation_names([*annotations, *class_annotations], SPRING_DATA_ANNOTATIONS)
    runtime_signals = _runtime_signal_matches(
        str(method.get("code") or "") + " " + str(method.get("signature") or ""),
        {
            "jpa_repository": r"\b(?:JpaRepository|CrudRepository|PagingAndSortingRepository|Repository)\b",
            "entity_manager": r"\bEntityManager\b|\.create(?:Native)?Query\s*\(",
            "criteria_api": r"\bCriteriaBuilder\b|\bCriteriaQuery\b",
            "specification": r"\bSpecification\s*<|\.toPredicate\s*\(",
        },
    )
    queries: List[Dict[str, Any]] = []
    for annotation in annotations:
        name = _annotation_name(annotation)
        if name != "Query":
            continue
        code = str(annotation.get("code") or "")
        query = _annotation_string_literal(code)
        queries.append(
            {
                "annotation": name,
                "line": _line_number(annotation),
                "code": code,
                "query": query,
                "native": "nativeQuery" in code and "true" in code.lower(),
                "uses_string_template": "${" in code or "#{" in code,
            }
        )
    return {
        "framework": "spring_data_jpa" if names or queries or runtime_signals else "",
        "annotations": names,
        "runtime_signals": runtime_signals,
        "queries": queries,
    }


def _webflux_semantics(
    method: Dict[str, Any],
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
    parameters: List[Dict[str, Any]],
    entry: Dict[str, Any],
    sources: List[Dict[str, Any]],
) -> Dict[str, Any]:
    text = " ".join(
        str(value or "")
        for value in (
            method.get("signature"),
            method.get("code"),
            *(param.get("typeFullName") or param.get("type") or "" for param in parameters),
        )
    )
    annotation_names = _matching_annotation_names(
        [*annotations, *class_annotations], WEBFLUX_ANNOTATIONS
    )
    reactive_types = sorted(
        set(re.findall(r"\b(?:Mono|Flux|ServerRequest|ServerResponse|WebClient)\b", text))
    )
    runtime_signals = _runtime_signal_matches(
        text,
        {
            "router_function": r"\b(?:RouterFunction|RouterFunctions|RequestPredicates)\b",
            "server_request_query_param": r"\bqueryParam\s*\(",
            "server_request_path_variable": r"\bpathVariable\s*\(",
            "webclient_uri": r"\bWebClient\b|\.uri\s*\(",
            "reactor_block": r"\.block\s*\(",
            "body_to_mono": r"\bbodyToMono\s*\(",
            "body_to_flux": r"\bbodyToFlux\s*\(",
            "reactor_map": r"\.map\s*\(",
            "reactor_flatmap": r"\.flatMap\s*\(",
            "reactor_zip": r"\.zipWith\s*\(",
        },
    )
    reactive_sources = _webflux_runtime_sources(text)
    reactive_pipeline = _webflux_pipeline_ops(text)
    return {
        "framework": (
            "spring_webflux"
            if (reactive_types or runtime_signals)
            and (entry.get("is_entry") or annotation_names or runtime_signals)
            else ""
        ),
        "is_reactive": bool(
            (reactive_types or runtime_signals)
            and (entry.get("is_entry") or annotation_names or runtime_signals)
        ),
        "reactive_types": reactive_types,
        "runtime_signals": runtime_signals,
        "sources": [*sources, *reactive_sources],
        "pipeline": reactive_pipeline,
    }


def _filter_interceptor_semantics(
    method: Dict[str, Any],
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    names = _matching_annotation_names(
        [*annotations, *class_annotations], FILTER_INTERCEPTOR_ANNOTATIONS
    )
    method_name = str(method.get("name") or "").strip()
    code = str(method.get("code") or "")
    runtime_signals = _runtime_signal_matches(
        code,
        {
            "filter_chain": r"\bFilterChain\b|\.doFilter\s*\(",
            "once_per_request_filter": r"\bOncePerRequestFilter\b",
            "filter_registration": r"\bFilterRegistrationBean\b",
            "handler_interceptor": r"\bHandlerInterceptor\b",
            "mapped_interceptor": r"\bMappedInterceptor\b",
            "request_wrapper": r"\bHttpServletRequestWrapper\b",
        },
    )
    runtime_names = {signal["name"] for signal in runtime_signals}
    is_filter = (
        method_name in {"doFilter"}
        or "FilterChain" in code
        or "ServletRequest" in code
        or "WebFilter" in names
        or bool(
            runtime_names
            & {"filter_chain", "once_per_request_filter", "filter_registration", "request_wrapper"}
        )
    )
    is_interceptor = (
        method_name in {"preHandle", "postHandle", "afterCompletion"}
        or "HandlerInterceptor" in code
        or bool(runtime_names & {"handler_interceptor", "mapped_interceptor"})
    )
    return {
        "framework": (
            "servlet_filter" if is_filter else ("spring_interceptor" if is_interceptor else "")
        ),
        "annotations": names,
        "runtime_signals": runtime_signals,
        "is_filter": is_filter,
        "is_interceptor": is_interceptor,
        "entry_method": method_name if is_filter or is_interceptor else "",
    }


def _messaging_semantics(
    method: Dict[str, Any],
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
    parameters: List[Dict[str, Any]],
) -> Dict[str, Any]:
    names = _matching_annotation_names([*annotations, *class_annotations], MESSAGING_ANNOTATIONS)
    runtime_signals = _runtime_signal_matches(
        str(method.get("code") or "") + " " + str(method.get("signature") or ""),
        {
            "kafka_template": r"\bKafkaTemplate\b|\.send\s*\(",
            "rabbit_template": r"\bRabbitTemplate\b|\.convertAndSend\s*\(",
            "jms_template": r"\bJmsTemplate\b|\.sendAndReceive\s*\(",
            "listener_container": r"\b(?:ConcurrentKafkaListenerContainerFactory|SimpleRabbitListenerContainerFactory|DefaultJmsListenerContainerFactory)\b",
            "message_handler": r"\bMessageHandler\b|\.handleMessage\s*\(",
        },
    )
    sources: List[Dict[str, Any]] = []
    for parameter in parameters:
        parameter_name = str(parameter.get("name") or "")
        for annotation in _annotation_list(parameter.get("annotations")):
            name = _annotation_name(annotation)
            if name not in MESSAGING_ANNOTATIONS:
                continue
            sources.append(
                {
                    "framework": "messaging",
                    "kind": "message_payload" if name == "Payload" else "message_metadata",
                    "annotation": name,
                    "parameter": parameter_name,
                    "external_name": _annotation_named_value(annotation) or parameter_name,
                    "line": _line_number(annotation),
                    "attacker_control": "external_message",
                }
            )
    return {
        "framework": "messaging" if names or runtime_signals else "",
        "annotations": names,
        "runtime_signals": runtime_signals,
        "is_messaging": bool(names or runtime_signals),
        "is_consumer": any(
            name in {"KafkaListener", "RabbitListener", "JmsListener", "MessageMapping"}
            for name in names
        )
        or any(
            signal["name"] in {"listener_container", "message_handler"}
            for signal in runtime_signals
        ),
        "sources": sources,
    }


def _scheduled_semantics(
    method: Dict[str, Any],
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    names = _matching_annotation_names([*annotations, *class_annotations], SCHEDULED_ANNOTATIONS)
    runtime_signals = _runtime_signal_matches(
        str(method.get("code") or ""),
        {
            "task_scheduler": r"\bTaskScheduler\b|\.schedule\s*\(",
            "scheduled_executor": r"\bScheduledExecutorService\b|\.scheduleAtFixedRate\s*\(",
        },
    )
    return {
        "framework": "scheduled" if "Scheduled" in names or runtime_signals else "",
        "annotations": names,
        "runtime_signals": runtime_signals,
        "is_scheduled": "Scheduled" in names or bool(runtime_signals),
    }


def _rpc_semantics(
    method: Dict[str, Any],
    annotations: List[Dict[str, Any]],
    class_annotations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    names = _matching_annotation_names([*annotations, *class_annotations], RPC_ANNOTATIONS)
    code = str(method.get("code") or "")
    method_name = str(method.get("name") or "")
    runtime_signals = _runtime_signal_matches(
        code + " " + str(method.get("signature") or ""),
        {
            "grpc_stream_observer": r"\bStreamObserver\b",
            "grpc_channel": r"\bManagedChannelBuilder\b|\bChannel\b",
            "grpc_stub": r"\b(?:BlockingStub|FutureStub|CoroutineStub)\b",
            "dubbo_reference": r"\bDubboReference\b|\bReferenceConfig\b",
            "feign_client": r"\bFeign\b|@FeignClient",
            "thrift_client": r"\bTServiceClient\b|\bTProcessor\b",
        },
    )
    inferred = []
    if method_name in {"invoke", "call"} and ("StreamObserver" in code or "Rpc" in code):
        inferred.append("inferred_rpc_handler")
    return {
        "framework": "rpc" if names or inferred or runtime_signals else "",
        "annotations": names + inferred,
        "runtime_signals": runtime_signals,
        "is_rpc": bool(names or inferred or runtime_signals),
        "sources": (
            [{"kind": "rpc_request", "attacker_control": "external_rpc"}]
            if names or inferred or runtime_signals
            else []
        ),
    }


def _annotation_list(value: Any) -> List[Dict[str, Any]]:
    if not value:
        return []
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, (list, tuple)):
        return []
    result: List[Dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            result.append(item)
    return result


def _matching_annotation_names(
    annotations: Iterable[Dict[str, Any]],
    allowed: Iterable[str],
) -> List[str]:
    allowed_set = set(allowed)
    result: List[str] = []
    for annotation in annotations:
        if not isinstance(annotation, dict):
            continue
        name = _annotation_name(annotation)
        if name in allowed_set and name not in result:
            result.append(name)
    return result


def _framework_runtime_ir(
    method: Dict[str, Any],
    entry: Dict[str, Any],
    sources: List[Dict[str, Any]],
    sql_templates: List[Dict[str, Any]],
    security: Dict[str, Any],
    data_access: Dict[str, Any],
    reactive: Dict[str, Any],
    filter_interceptor: Dict[str, Any],
    messaging: Dict[str, Any],
    scheduled: Dict[str, Any],
    rpc: Dict[str, Any],
) -> Dict[str, Any]:
    """Normalize framework facts into a shared runtime IR for downstream evidence."""
    method_name = str(
        method.get("qualified_name") or method.get("fullName") or method.get("name") or ""
    )
    code = str(method.get("code") or "")
    entrypoints: List[Dict[str, Any]] = []
    if entry.get("is_entry"):
        for path in entry.get("paths") or [""]:
            entrypoints.append(
                {
                    "kind": "spring_mvc_route",
                    "framework": "spring_mvc",
                    "function": method_name,
                    "path": path,
                    "http_methods": entry.get("http_methods") or ["ANY"],
                    "annotations": entry.get("annotations") or [],
                    "precision": "annotation_path_merge",
                }
            )
    if messaging.get("is_consumer"):
        entrypoints.append(
            {
                "kind": "message_consumer",
                "framework": "messaging",
                "function": method_name,
                "annotations": messaging.get("annotations") or [],
                "precision": "listener_annotation",
            }
        )
    if scheduled.get("is_scheduled"):
        entrypoints.append(
            {
                "kind": "scheduled_job",
                "framework": "scheduled",
                "function": method_name,
                "annotations": scheduled.get("annotations") or [],
                "attacker_controlled": False,
                "precision": "scheduled_annotation_or_scheduler_signal",
            }
        )
    if rpc.get("is_rpc"):
        entrypoints.append(
            {
                "kind": "rpc_endpoint_or_client",
                "framework": "rpc",
                "function": method_name,
                "annotations": rpc.get("annotations") or [],
                "precision": "rpc_annotation_or_runtime_signal",
            }
        )
    if filter_interceptor.get("is_filter") or filter_interceptor.get("is_interceptor"):
        entrypoints.append(
            {
                "kind": "servlet_filter_or_interceptor",
                "framework": filter_interceptor.get("framework"),
                "function": method_name,
                "entry_method": filter_interceptor.get("entry_method"),
                "precision": "servlet_boundary_signal",
            }
        )

    ir_sources = [dict(src, runtime_kind="source") for src in sources]
    for src in reactive.get("sources") or []:
        if isinstance(src, dict) and src not in ir_sources:
            ir_sources.append(dict(src, runtime_kind="source"))
    for src in messaging.get("sources") or []:
        if isinstance(src, dict):
            ir_sources.append(dict(src, runtime_kind="source"))
    for src in rpc.get("sources") or []:
        if isinstance(src, dict):
            ir_sources.append(dict(src, runtime_kind="source", framework="rpc"))

    bindings = _bean_runtime_bindings(code)
    propagation_edges = _runtime_call_edges(code, method_name)
    sinks: List[Dict[str, Any]] = []
    for template in sql_templates:
        if not isinstance(template, dict):
            continue
        sinks.append(
            {
                "kind": "mybatis_sql_template",
                "framework": "mybatis",
                "line": template.get("line"),
                "uses_text_substitution": template.get("uses_text_substitution"),
                "text_substitution_variables": template.get("text_substitution_variables") or [],
                "parameter_binding_variables": template.get("parameter_binding_variables") or [],
                "dynamic_sql_tags": template.get("dynamic_sql_tags") or [],
                "risk": "high" if template.get("uses_text_substitution") else "contextual",
            }
        )
    if data_access.get("queries"):
        for query in data_access.get("queries") or []:
            if isinstance(query, dict):
                sinks.append(
                    {
                        "kind": "spring_data_query",
                        "framework": "spring_data_jpa",
                        "query": query.get("query"),
                        "native": query.get("native"),
                        "uses_string_template": query.get("uses_string_template"),
                    }
                )
    for signal in reactive.get("runtime_signals") or []:
        if isinstance(signal, dict) and signal.get("name") == "webclient_uri":
            sinks.append(
                {
                    "kind": "webclient_uri",
                    "framework": "spring_webflux",
                    "snippet": signal.get("snippet"),
                }
            )

    runtime_configs: List[Dict[str, Any]] = []
    for section_name, section in (
        ("security", security),
        ("data_access", data_access),
        ("reactive", reactive),
        ("filter_interceptor", filter_interceptor),
        ("messaging", messaging),
        ("scheduled", scheduled),
        ("rpc", rpc),
    ):
        for signal in section.get("runtime_signals") or []:
            if isinstance(signal, dict):
                runtime_configs.append({"section": section_name, **signal})

    guards = []
    for annotation in security.get("annotations") or []:
        guards.append({"kind": "method_security_annotation", "annotation": annotation})
    guards.extend(security.get("policies") or [])

    return {
        "schema": "java_framework_runtime_ir.v1",
        "entrypoints": entrypoints,
        "sources": ir_sources,
        "bindings": bindings,
        "propagation_edges": propagation_edges,
        "sinks": sinks,
        "guards": guards,
        "runtime_configs": runtime_configs,
        "security_policies": security.get("policies") or [],
        "reactive_pipeline": reactive.get("pipeline") or [],
        "model_capabilities": _framework_model_capabilities(
            entrypoints=entrypoints,
            sources=ir_sources,
            bindings=bindings,
            sinks=sinks,
            guards=guards,
            runtime_configs=runtime_configs,
            reactive_pipeline=reactive.get("pipeline") or [],
        ),
        "precision_tiers": {
            "annotation_entries": "framework_binding_flow",
            "bean_bindings": "framework_binding_flow" if bindings else "not_observed",
            "reactive_pipeline": (
                "source_level_approx" if reactive.get("pipeline") else "not_observed"
            ),
            "security_policy": (
                "framework_binding_flow" if security.get("policies") else "not_observed"
            ),
            "dynamic_proxy_or_aop": "not_modeled",
        },
        "limitations": [
            "Runtime IR is a bounded static approximation; it does not execute Spring bean resolution, AOP proxies, or reactive scheduling.",
            "Validator must confirm runtime profile, bean selection, sanitizers, allowlists, and security filter-chain order.",
        ],
    }


def _framework_model_capabilities(
    *,
    entrypoints: List[Dict[str, Any]],
    sources: List[Dict[str, Any]],
    bindings: List[Dict[str, Any]],
    sinks: List[Dict[str, Any]],
    guards: List[Dict[str, Any]],
    runtime_configs: List[Dict[str, Any]],
    reactive_pipeline: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "entrypoints": bool(entrypoints),
        "sources": bool(sources),
        "bean_bindings": bool(bindings),
        "sinks": bool(sinks),
        "guards": bool(guards),
        "runtime_configs": bool(runtime_configs),
        "reactive_pipeline": bool(reactive_pipeline),
        "unsupported_or_approximate": [
            "spring_profile_condition_evaluation",
            "full_security_filter_chain_order",
            "aop_proxy_dispatch",
            "runtime_reflection_registration",
            "webflux_operator_level_taint",
            "mybatis_ognl_branch_execution",
        ],
    }


def _spring_security_policy_graph(code: str, annotations: List[str]) -> List[Dict[str, Any]]:
    text = str(code or "")
    policies: List[Dict[str, Any]] = []
    for pattern, decision in (
        (
            r"(?:requestMatchers|antMatchers|mvcMatchers)\s*\((?P<matcher>[^)]*)\)\s*\.\s*permitAll\s*\(",
            "permit_all",
        ),
        (
            r"(?:requestMatchers|antMatchers|mvcMatchers)\s*\((?P<matcher>[^)]*)\)\s*\.\s*authenticated\s*\(",
            "authenticated",
        ),
        (
            r"(?:requestMatchers|antMatchers|mvcMatchers)\s*\((?P<matcher>[^)]*)\)\s*\.\s*hasRole\s*\((?P<role>[^)]*)\)",
            "has_role",
        ),
        (r"anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(", "permit_all"),
        (r"anyRequest\s*\(\s*\)\s*\.\s*authenticated\s*\(", "authenticated"),
    ):
        for match in re.finditer(pattern, text, re.S):
            matcher_text = match.groupdict().get("matcher") or "anyRequest"
            policies.append(
                {
                    "kind": "spring_security_authorization_policy",
                    "decision": decision,
                    "matcher": _java_string_literals(matcher_text) or [matcher_text.strip()],
                    "role": (match.groupdict().get("role") or "").strip().strip('"'),
                    "snippet": text[
                        max(0, match.start() - 80) : min(len(text), match.end() + 120)
                    ].strip(),
                    "precision": "security_dsl_matcher_chain",
                }
            )
    if re.search(r"\bcsrf\s*\(\s*\)\.disable\s*\(", text):
        policies.append(
            {
                "kind": "spring_security_csrf_policy",
                "decision": "csrf_disabled",
                "matcher": ["*"],
                "precision": "security_dsl_csrf_disable",
            }
        )
    if re.search(r"\bweb\.ignoring\s*\(", text):
        policies.append(
            {
                "kind": "spring_security_filter_chain_bypass",
                "decision": "web_ignored",
                "matcher": _java_string_literals(text) or ["unknown"],
                "precision": "web_security_ignoring_signal",
            }
        )
    for annotation in annotations:
        if annotation in {
            "PreAuthorize",
            "PostAuthorize",
            "Secured",
            "RolesAllowed",
            "PermitAll",
            "DenyAll",
        }:
            policies.append(
                {
                    "kind": "method_security_policy",
                    "decision": annotation,
                    "matcher": ["method"],
                    "precision": "method_security_annotation",
                }
            )
    return policies


def _webflux_runtime_sources(text: str) -> List[Dict[str, Any]]:
    sources: List[Dict[str, Any]] = []
    for name in re.findall(r"\bqueryParam\s*\(\s*\"([^\"]+)\"", str(text or "")):
        sources.append(
            {
                "framework": "spring_webflux",
                "kind": "webflux_query_param",
                "external_name": name,
                "source_expression": f'queryParam("{name}")',
                "attacker_control": "external_http_request",
            }
        )
    for name in re.findall(r"\bpathVariable\s*\(\s*\"([^\"]+)\"", str(text or "")):
        sources.append(
            {
                "framework": "spring_webflux",
                "kind": "webflux_path_variable",
                "external_name": name,
                "source_expression": f'pathVariable("{name}")',
                "attacker_control": "external_http_request",
            }
        )
    if re.search(r"\bbodyToMono\s*\(", str(text or "")):
        sources.append(
            {
                "framework": "spring_webflux",
                "kind": "webflux_request_body",
                "source_expression": "bodyToMono",
                "attacker_control": "external_http_request",
            }
        )
    return sources


def _webflux_pipeline_ops(text: str) -> List[Dict[str, Any]]:
    ops: List[Dict[str, Any]] = []
    for match in re.finditer(
        r"\.(queryParam|pathVariable|bodyToMono|bodyToFlux|map|flatMap|filter|zipWith|switchIfEmpty|uri|retrieve|block)\s*\(",
        str(text or ""),
    ):
        op = match.group(1)
        if op in {"queryParam", "pathVariable", "bodyToMono", "bodyToFlux"}:
            kind = "source"
        elif op in {"uri", "retrieve", "block"}:
            kind = "sink_or_boundary"
        else:
            kind = "propagation"
        ops.append(
            {
                "operator": op,
                "kind": kind,
                "position": match.start(),
                "snippet": str(text or "")[
                    max(0, match.start() - 60) : min(len(str(text or "")), match.end() + 100)
                ].strip(),
            }
        )
    return ops


def _bean_runtime_bindings(code: str) -> List[Dict[str, Any]]:
    text = str(code or "")
    bindings: List[Dict[str, Any]] = []
    for match in re.finditer(
        r"(?:(@Autowired|@Resource|@Inject)\s+)?(?:private|protected|public)?\s*(?:final\s+)?"
        r"(?P<type>[A-Z][\w$.<>]*)\s+(?P<field>[a-zA-Z_$][\w$]*)\s*;",
        text,
    ):
        if match.group(1) or match.group("field"):
            bindings.append(
                {
                    "kind": "spring_bean_field",
                    "field": match.group("field"),
                    "declared_type": _raw_java_type(match.group("type")),
                    "annotation": (match.group(1) or "").lstrip("@"),
                    "precision": "field_type_match",
                }
            )
    for match in re.finditer(
        r"this\.(?P<field>[A-Za-z_$][\w$]*)\s*=\s*(?P<param>[A-Za-z_$][\w$]*)\s*;", text
    ):
        bindings.append(
            {
                "kind": "constructor_or_setter_assignment",
                "field": match.group("field"),
                "parameter": match.group("param"),
                "precision": "assignment_name_match",
            }
        )
    for match in re.finditer(r"@(?:Qualifier|Resource)\s*\(\s*(?:name\s*=\s*)?\"([^\"]+)\"", text):
        bindings.append(
            {
                "kind": "spring_bean_qualifier",
                "bean_name": match.group(1),
                "precision": "qualifier_annotation_literal",
            }
        )
    return bindings


def _runtime_call_edges(code: str, method_name: str) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    for match in re.finditer(
        r"([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", str(code or "")
    ):
        target = match.group(1)
        callee = match.group(2)
        if target in {"http", "cpg", "System", "Runtime", "WebClient"}:
            continue
        edges.append(
            {
                "kind": "method_argument",
                "from": method_name,
                "target": target,
                "callee": callee,
                "arguments": [arg.strip() for arg in _split_java_arguments(match.group(3))],
                "precision": "call_argument_syntax",
            }
        )
    return edges


def _mybatis_dynamic_tags(sql: str) -> List[str]:
    tags = re.findall(
        r"<\s*(if|choose|when|otherwise|foreach|trim|where|set|bind)\b", str(sql or ""), re.I
    )
    result: List[str] = []
    for tag in tags:
        lowered = tag.lower()
        if lowered not in result:
            result.append(lowered)
    return result


def _java_string_literals(text: str) -> List[str]:
    return re.findall(r'"([^"]*)"', str(text or ""))


def _raw_java_type(type_name: str) -> str:
    return re.sub(r"<.*>", "", str(type_name or "")).strip()


def _split_java_arguments(text: str) -> List[str]:
    args: List[str] = []
    current: List[str] = []
    depth = 0
    quote = ""
    for ch in str(text or ""):
        if quote:
            current.append(ch)
            if ch == "\\":
                continue
            if ch == quote:
                quote = ""
            continue
        if ch in {'"', "'"}:
            quote = ch
            current.append(ch)
            continue
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            arg = "".join(current).strip()
            if arg:
                args.append(arg)
            current = []
            continue
        current.append(ch)
    arg = "".join(current).strip()
    if arg:
        args.append(arg)
    return args


def _runtime_signal_names(section: Dict[str, Any]) -> List[str]:
    signals = section.get("runtime_signals") if isinstance(section, dict) else []
    if not isinstance(signals, list):
        return []
    names: List[str] = []
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        name = str(signal.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _runtime_signal_matches(code: str, patterns: Dict[str, str]) -> List[Dict[str, Any]]:
    text = str(code or "")
    signals: List[Dict[str, Any]] = []
    for name, pattern in patterns.items():
        match = re.search(pattern, text)
        if not match:
            continue
        signals.append(
            {
                "name": name,
                "snippet": text[
                    max(0, match.start() - 80) : min(len(text), match.end() + 120)
                ].strip(),
            }
        )
    return signals


def _parameter_list(value: Any) -> List[Dict[str, Any]]:
    return _annotation_list(value)


def _annotation_name(annotation: Dict[str, Any]) -> str:
    raw = str(annotation.get("name") or annotation.get("fullName") or "").strip()
    return raw.rsplit(".", 1)[-1]


def _line_number(annotation: Dict[str, Any]) -> int:
    try:
        value = int(annotation.get("lineNumber", annotation.get("line", -1)))
    except (TypeError, ValueError):
        value = -1
    return value


def _annotation_named_value(annotation: Dict[str, Any]) -> str:
    code = str(annotation.get("code") or "")
    match = re.search(r'@\w+(?:\([^"]*"([^"]+)")', code)
    if match:
        return match.group(1)
    match = re.search(r'\b(?:name|value)\s*=\s*"([^"]+)"', code)
    return match.group(1) if match else ""


def _annotation_paths(annotation: Dict[str, Any]) -> List[str]:
    code = str(annotation.get("code") or "")
    values = re.findall(r'"([^"]*)"', code)
    paths = [value for value in values if value.startswith("/") or value == ""]
    if not paths:
        named = _annotation_named_value(annotation)
        if named.startswith("/") or named == "":
            paths = [named]
    return paths


def _annotation_http_methods(annotation: Dict[str, Any]) -> List[str]:
    code = str(annotation.get("code") or "")
    methods = re.findall(r"RequestMethod\.([A-Z]+)", code)
    return sorted(dict.fromkeys(methods))


def _annotation_string_literal(code: str) -> str:
    match = re.search(r'@\w+\s*\(\s*"((?:\\.|[^"\\])*)"', str(code or ""))
    if not match:
        return ""
    return match.group(1).replace('\\"', '"')


def _join_paths(class_paths: Iterable[str], method_paths: Iterable[str]) -> List[str]:
    result: List[str] = []
    for left in class_paths:
        for right in method_paths:
            joined = _join_path(str(left or ""), str(right or ""))
            if joined not in result:
                result.append(joined)
    return result


def _join_path(left: str, right: str) -> str:
    if not left and not right:
        return "/"
    if not left:
        return right or "/"
    if not right:
        return left or "/"
    return "/" + "/".join(part.strip("/") for part in (left, right) if part.strip("/"))

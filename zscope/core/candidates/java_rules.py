"""Local Java security candidate generation.

These rules are intentionally evidence-first and path-light. They identify high
value Java sinks and framework-adjacent hazards, then leave exploitability and
guard sufficiency to the existing validator pipeline.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Pattern, Sequence

from .cpp_domains import (
    ResolvedRuleDescriptor,
    resolve_emitter_descriptor,
    resolve_rule_descriptor,
)

if TYPE_CHECKING:
    from ...orchestration.candidates import CandidateTicket


@dataclass(frozen=True)
class JavaLine:
    number: int
    raw: str
    text: str
    index: int


@dataclass(frozen=True)
class JavaRule:
    rule_id: str
    defect_class: str
    skill: str
    cwe: str
    pattern: Pattern[str]
    sink_label: str
    description: str
    root_cause: str
    suggested_fix: str
    confidence: float = 0.72
    impact_level: str = "high"
    guard_terms: Sequence[str] = ()


class JavaRuleCandidateGenerator:
    """Generate Java injection/resource/crypto candidates from method source."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _DEFAULT_GUARD_TERMS = (
        "validate",
        "sanitize",
        "escape",
        "normalize",
        "canonical",
        "allowlist",
        "whitelist",
        "check",
        "authorize",
        "permission",
        "hasRole",
        "hasAuthority",
    )

    def __init__(self, rule_policy: Optional[Any] = None):
        self.rule_policy = rule_policy

    _RULES: Sequence[JavaRule] = (
        JavaRule(
            rule_id="java_sql_statement_execute",
            defect_class="sql_injection",
            skill="java_injection",
            cwe="CWE-89",
            pattern=re.compile(
                r"\b(?:Statement|PreparedStatement)?\s*\w*\.execute(?:Query|Update|Batch|LargeUpdate)?\s*\("
            ),
            sink_label="SQL execute",
            description="SQL 执行 API 使用动态参数，可能存在 SQL 注入或错误的参数化使用。",
            root_cause="数据库查询进入执行汇点前缺少可证明的参数化绑定或输入约束。",
            suggested_fix="使用 PreparedStatement/JPA 参数绑定/MyBatis #{}，避免拼接 SQL，并验证动态表名/排序字段。",
            confidence=0.68,
            guard_terms=("PreparedStatement", "setString", "setInt", "setLong", "createQuery"),
        ),
        JavaRule(
            rule_id="java_jdbc_concatenated_sql",
            defect_class="sql_injection",
            skill="java_injection",
            cwe="CWE-89",
            pattern=re.compile(
                r"\b(?:String\s+)?\w*sql\w*\s*=\s*\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\"\s*\+",
                re.I,
            ),
            sink_label="concatenated JDBC SQL string",
            description="JDBC/JdbcTemplate SQL 字符串由外部参数拼接构造。",
            root_cause="请求参数进入 SQL 字符串构造阶段，后续执行 API 无法提供参数化保护。",
            suggested_fix="使用 PreparedStatement/JdbcTemplate 参数数组或命名参数绑定；动态字段必须 allowlist。",
            confidence=0.84,
            guard_terms=(
                "setString",
                "setInt",
                "NamedParameterJdbcTemplate",
                "CriteriaBuilder",
                "allowlist",
            ),
        ),
        JavaRule(
            rule_id="java_jdbc_fake_prepared_statement",
            defect_class="sql_injection",
            skill="java_injection",
            cwe="CWE-89",
            pattern=re.compile(r"\b\w+\.prepareStatement\s*\(\s*\w*sql\w*\s*\)", re.I),
            sink_label="PreparedStatement from dynamic SQL variable",
            description="PreparedStatement 使用已经拼接好的 SQL 变量创建，可能是伪预编译。",
            root_cause="SQL 字符串在 prepareStatement 之前已拼接外部输入，未使用占位符绑定。",
            suggested_fix="把用户输入通过 ? 占位符和 setXxx 绑定，不要把完整 SQL 作为 execute 参数传入。",
            confidence=0.78,
            guard_terms=("setString", "setInt", "setLong", "setObject", "?"),
        ),
        JavaRule(
            rule_id="java_mybatis_dollar_substitution",
            defect_class="sql_injection",
            skill="java_injection",
            cwe="CWE-89",
            pattern=re.compile(r"\$\{[^}]+}"),
            sink_label="MyBatis ${}",
            description="MyBatis `${}` 文本替换会把输入直接拼入 SQL。",
            root_cause="使用字符串替换而非参数绑定表达动态 SQL。",
            suggested_fix="改用 `#{}` 参数绑定；动态标识符必须经过 allowlist。",
            confidence=0.82,
        ),
        JavaRule(
            rule_id="java_jpa_dynamic_query",
            defect_class="jpa_injection",
            skill="java_injection",
            cwe="CWE-89",
            pattern=re.compile(
                r"\b(?:EntityManager|Session)\s*\w*|\.create(?:Native)?Query\s*\(|\.createSQLQuery\s*\("
            ),
            sink_label="JPA/JPQL query construction",
            description="JPA/JPQL/NativeQuery 可能使用字符串拼接构造查询。",
            root_cause="外部输入进入 JPQL/SQL 查询字符串前缺少参数绑定。",
            suggested_fix="使用命名参数/位置参数绑定，动态字段或排序必须 allowlist。",
            confidence=0.68,
            guard_terms=("setParameter", "ParameterExpression", "CriteriaBuilder", "allowlist"),
        ),
        JavaRule(
            rule_id="java_nosql_query_injection",
            defect_class="nosql_injection",
            skill="java_injection",
            cwe="CWE-943",
            pattern=re.compile(
                r"\b(?:BasicQuery|Document\.parse|Criteria\.where|QueryBuilders|BoolQueryBuilder|Aggregation\.newAggregation|Filters\.)\b|\.regex\s*\("
            ),
            sink_label="NoSQL/raw query construction",
            description="MongoDB/Elasticsearch 等 NoSQL 查询可能拼接外部输入或 raw JSON。",
            root_cause="外部输入进入 NoSQL 查询 DSL/JSON/filter 前缺少结构化绑定或转义。",
            suggested_fix="使用结构化查询 API，避免 raw JSON 拼接，并限制 regex/field/operator。",
            confidence=0.66,
            guard_terms=("Criteria", "Filters.eq", "allowlist", "Pattern.quote"),
        ),
        JavaRule(
            rule_id="java_command_execution",
            defect_class="command_injection",
            skill="java_injection",
            cwe="CWE-78",
            pattern=re.compile(
                r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder|ProcessBuilder\s*\()"
            ),
            sink_label="process execution",
            description="进程执行 API 可能接收外部可控命令或参数。",
            root_cause="命令/参数进入系统执行汇点前缺少 allowlist 或固定参数边界。",
            suggested_fix="使用固定命令和分离参数数组；对用户可控参数做 allowlist，避免 shell 拼接。",
            confidence=0.76,
        ),
        JavaRule(
            rule_id="java_path_traversal_file_api",
            defect_class="path_traversal",
            skill="java_web_security",
            cwe="CWE-22",
            pattern=re.compile(
                r"\b(?:new\s+File|Paths\.get|Path\.of|Files\.(?:read|write|copy|move|delete|newInputStream|newOutputStream))\s*\("
            ),
            sink_label="file/path API",
            description="文件路径 API 可能使用外部输入构造路径，存在路径穿越风险。",
            root_cause="路径进入文件系统汇点前缺少规范化、根目录约束或 allowlist。",
            suggested_fix="对路径执行 normalize/canonicalize，并验证解析后路径仍位于允许根目录下。",
            confidence=0.66,
            impact_level="medium",
            guard_terms=("normalize", "toRealPath", "getCanonicalPath", "startsWith", "resolve"),
        ),
        JavaRule(
            rule_id="java_ssrf_http_client",
            defect_class="ssrf",
            skill="java_web_security",
            cwe="CWE-918",
            pattern=re.compile(
                r"\b(?:new\s+URL|URI\.create|HttpClient\.newHttpClient|RestTemplate\.|WebClient\.|OkHttpClient|HttpURLConnection)\b"
            ),
            sink_label="outbound URL/client",
            description="出站 HTTP/URL API 可能使用外部可控地址，存在 SSRF 风险。",
            root_cause="URL/host 进入出站请求汇点前缺少协议、主机、网段和重定向约束。",
            suggested_fix="对 scheme/host/port 做 allowlist，阻止内网/metadata 地址，并限制重定向。",
            confidence=0.7,
            guard_terms=("allowlist", "isPrivate", "InetAddress", "getHost", "startsWith"),
        ),
        JavaRule(
            rule_id="java_file_upload_path",
            defect_class="file_upload",
            skill="java_web_security",
            cwe="CWE-434",
            pattern=re.compile(r"\bMultipartFile\b|\.getOriginalFilename\s*\(|\.transferTo\s*\("),
            sink_label="file upload handling",
            description="文件上传处理可能信任原始文件名、类型或直接写入目标路径。",
            root_cause="上传文件名/内容类型进入文件系统或业务处理前缺少扩展名、MIME、大小和路径校验。",
            suggested_fix="服务端生成文件名，限制扩展名/MIME/大小，写入隔离目录并执行恶意内容检测。",
            confidence=0.64,
            impact_level="medium",
            guard_terms=("getContentType", "getSize", "allowlist", "normalize", "startsWith"),
        ),
        JavaRule(
            rule_id="java_object_deserialization",
            defect_class="unsafe_deserialization",
            skill="java_deserialization",
            cwe="CWE-502",
            pattern=re.compile(
                r"\b(?:new\s+ObjectInputStream|\.readObject\s*\(|enableDefaultTyping|activateDefaultTyping)\b"
            ),
            sink_label="object deserialization",
            description="对象反序列化或 Jackson default typing 可能处理不可信数据。",
            root_cause="反序列化入口缺少类型 allowlist 或安全反序列化边界。",
            suggested_fix="避免原生 Java 反序列化；使用 ObjectInputFilter/类型 allowlist，并禁用危险 default typing。",
            confidence=0.8,
        ),
        JavaRule(
            rule_id="java_third_party_deserialization",
            defect_class="unsafe_deserialization",
            skill="java_deserialization",
            cwe="CWE-502",
            pattern=re.compile(
                r"\b(?:JSON\.parseObject|JSON\.parse|ObjectMapper\.enableDefaultTyping|activateDefaultTyping|new\s+XStream|Yaml\s*\(|new\s+Yaml|loadAs\s*\(|\.fromXML\s*\()"
            ),
            sink_label="third-party deserialization",
            description="Fastjson/Jackson/XStream/SnakeYAML 等反序列化入口可能处理不可信数据。",
            root_cause="启用危险类型解析或对外部输入执行对象反序列化。",
            suggested_fix="禁用 autoType/default typing，使用安全解析模式、类型 allowlist 和最新依赖版本。",
            confidence=0.78,
        ),
        JavaRule(
            rule_id="java_xxe_factory",
            defect_class="xxe",
            skill="java_deserialization",
            cwe="CWE-611",
            pattern=re.compile(
                r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReaderFactory|XMLReader|SAXReader)\b"
            ),
            sink_label="XML parser factory",
            description="XML 解析器工厂可能未禁用外部实体，存在 XXE 风险。",
            root_cause="创建 XML parser 后未看到禁用 DOCTYPE/外部实体/外部 DTD 的配置。",
            suggested_fix="禁用 DOCTYPE、external-general-entities、external-parameter-entities 和外部 DTD。",
            confidence=0.62,
            impact_level="medium",
            guard_terms=(
                "disallow-doctype-decl",
                "external-general-entities",
                "external-parameter-entities",
                "SUPPORT_DTD",
                "isSupportingExternalEntities",
            ),
        ),
        JavaRule(
            rule_id="java_xmldecoder_readobject",
            defect_class="unsafe_deserialization",
            skill="java_deserialization",
            cwe="CWE-502",
            pattern=re.compile(
                r"\b(?:new\s+java\.beans\.XMLDecoder|new\s+XMLDecoder|XMLDecoder\s*\()"
            ),
            sink_label="XMLDecoder deserialization",
            description="XMLDecoder 会实例化并调用 XML 中描述的对象/方法，处理不可信 XML 时可导致代码执行。",
            root_cause="外部输入构造 XMLDecoder 输入流并调用 readObject，缺少安全解析边界。",
            suggested_fix="不要使用 XMLDecoder 解析外部输入；改用安全 XML/JSON 解析并固定数据模型。",
            confidence=0.86,
        ),
        JavaRule(
            rule_id="java_template_injection",
            defect_class="template_injection",
            skill="java_injection",
            cwe="CWE-94",
            pattern=re.compile(
                r"\b(?:Freemarker|freemarker\.template\.Configuration|VelocityEngine|TemplateEngine|StringTemplateResolver|Mustache|Handlebars)\b"
                r"|\.process\s*\(|\.merge\s*\(|\.createTemplate\s*\("
            ),
            sink_label="template rendering",
            description="模板内容或表达式若来自外部输入，可能导致服务端模板注入。",
            root_cause="外部输入被当作模板源码或表达式执行，而不是普通数据模型值。",
            suggested_fix="模板源码固定在服务端，仅把用户输入作为转义后的模型数据传入，并限制表达式能力。",
            confidence=0.64,
        ),
        JavaRule(
            rule_id="java_sensitive_logging",
            defect_class="sensitive_log",
            skill="java_web_security",
            cwe="CWE-532",
            pattern=re.compile(
                r"\b(?:log|logger)\.(?:trace|debug|info|warn|error)\s*\([^;]*(?:password|passwd|secret|token|authorization|cookie|set-cookie|credential)",
                re.I,
            ),
            sink_label="sensitive logging",
            description="日志输出可能包含密码、token、cookie 或 Authorization 等敏感信息。",
            root_cause="敏感数据进入日志汇点前缺少脱敏或字段过滤。",
            suggested_fix="对敏感字段做结构化脱敏，禁止记录完整凭据和认证头。",
            confidence=0.62,
            impact_level="medium",
            guard_terms=("mask", "redact", "sanitize", "hash"),
        ),
        JavaRule(
            rule_id="java_header_injection",
            defect_class="header_injection",
            skill="java_web_security",
            cwe="CWE-113",
            pattern=re.compile(r"\b(?:setHeader|addHeader|setDateHeader|addDateHeader)\s*\("),
            sink_label="HTTP header write",
            description="响应头值可能来自外部输入，存在响应拆分或不安全 header 写入风险。",
            root_cause="外部输入进入响应头前缺少 CR/LF 过滤和 header-specific allowlist。",
            suggested_fix="拒绝 CR/LF，使用框架安全 API，并对 Location/Set-Cookie 等敏感头做专门校验。",
            confidence=0.56,
            impact_level="medium",
            guard_terms=("\\r", "\\n", "replace", "contains", "allowlist"),
        ),
        JavaRule(
            rule_id="java_insecure_cookie_flags",
            defect_class="insecure_cookie",
            skill="java_web_security",
            cwe="CWE-614",
            pattern=re.compile(r"\bnew\s+Cookie\s*\(|ResponseCookie\.from\s*\(|\.addCookie\s*\("),
            sink_label="cookie creation",
            description="认证或会话 Cookie 可能缺少 HttpOnly/Secure/SameSite 属性。",
            root_cause="创建 Cookie 后未看到安全属性设置或使用默认弱配置。",
            suggested_fix="为敏感 Cookie 设置 HttpOnly、Secure、SameSite，并限制 Path/Domain/Max-Age。",
            confidence=0.54,
            impact_level="medium",
            guard_terms=("setHttpOnly", "setSecure", "SameSite", "httpOnly", "secure"),
        ),
        JavaRule(
            rule_id="java_cors_wildcard",
            defect_class="cors_misconfiguration",
            skill="java_web_security",
            cwe="CWE-942",
            pattern=re.compile(
                r'@CrossOrigin\s*\([^)]*"\*"|allowedOrigins\s*\([^)]*"\*"|allowedOriginPatterns\s*\([^)]*"\*"|CorsConfiguration\.ALL',
                re.I,
            ),
            sink_label="permissive CORS",
            description="CORS 来源配置过宽，可能允许任意站点读取敏感响应。",
            root_cause="允许 `*` 或宽泛 origin pattern，且可能与凭据请求组合使用。",
            suggested_fix="配置精确 origin allowlist，避免和 allowCredentials(true) 组合。",
            confidence=0.7,
            impact_level="medium",
            guard_terms=("allowCredentials(false)", "allowedOrigins", "allowlist"),
        ),
        JavaRule(
            rule_id="java_spring_security_permit_all",
            defect_class="authz_bypass",
            skill="java_authz",
            cwe="CWE-862",
            pattern=re.compile(
                r"\b(?:permitAll\s*\(|antMatchers\s*\(\s*\"/\*\*\"|requestMatchers\s*\(\s*\"/\*\*\"|web\.ignoring\s*\(|csrf\s*\(\s*\)\.disable\s*\()"
            ),
            sink_label="Spring Security broad allow/disable",
            description="Spring Security 配置可能过宽或禁用 CSRF，导致认证/授权绕过。",
            root_cause="全局 permitAll、忽略安全过滤器或禁用 CSRF 缺少上下文约束。",
            suggested_fix="按路径最小授权，避免 `/**` 放行，表单/浏览器会话场景保持 CSRF 保护。",
            confidence=0.68,
            impact_level="high",
            guard_terms=("authenticated", "hasRole", "hasAuthority", "csrfTokenRepository"),
        ),
        JavaRule(
            rule_id="java_sensitive_state_change_missing_authz",
            defect_class="authz_bypass",
            skill="java_authz",
            cwe="CWE-862",
            pattern=re.compile(
                r"\b(?:@DeleteMapping|@PatchMapping|deleteById\s*\(|\.(?:delete|remove|update|save|disable|enable)\s*\()"
            ),
            sink_label="sensitive state-changing operation",
            description="敏感状态变更操作可能缺少认证、授权或对象归属检查。",
            root_cause="外部可触发的删除/更新操作在进入持久化或业务状态变更前缺少可证明的权限检查。",
            suggested_fix="为敏感操作增加 @PreAuthorize/@Secured、角色/权限检查和对象 owner/tenant 校验，并确保 Spring Security 配置不会放行该路径。",
            confidence=0.74,
            impact_level="high",
            guard_terms=(
                "@PreAuthorize",
                "@Secured",
                "hasRole",
                "hasAuthority",
                "SecurityContext",
                "Principal",
                "Authentication",
                "owner",
                "tenant",
            ),
        ),
        JavaRule(
            rule_id="java_missing_object_authorization",
            defect_class="authz_bypass",
            skill="java_authz",
            cwe="CWE-639",
            pattern=re.compile(
                r"\b(?:find|get|query|select)\w*(?:User|Account|Order|Info|ById|ByName|ByUsername)\s*\("
                r"|\.select\w*\s*\([^)]*(?:username|userId|uid|id|orderId|accountId)",
                re.I,
            ),
            sink_label="object lookup without owner check",
            description="对象级查询可能直接使用外部传入的用户、订单或账户标识，缺少 owner/tenant/principal 校验。",
            root_cause="外部标识进入对象查询后未看到与当前认证主体、租户或角色绑定的授权检查。",
            suggested_fix="在查询条件中绑定当前 principal/tenant，或在返回前校验 owner/tenant/role。",
            confidence=0.72,
            impact_level="high",
            guard_terms=(
                "Principal",
                "Authentication",
                "SecurityContext",
                "currentUser",
                "owner",
                "tenant",
                "@PreAuthorize",
            ),
        ),
        JavaRule(
            rule_id="java_filter_unconditional_chain",
            defect_class="authz_bypass",
            skill="java_authz",
            cwe="CWE-862",
            pattern=re.compile(r"\b\w+\.doFilter\s*\("),
            sink_label="servlet filter chain continuation",
            description="Servlet filter 在认证失败、缺失或未验证 token 时仍继续调用 FilterChain.doFilter。",
            root_cause="认证过滤器未在缺失/无效凭据时中断请求，导致下游处理链继续执行。",
            suggested_fix="认证缺失或失败时返回 401/403 并停止调用 chain.doFilter；只在验证成功后继续过滤链。",
            confidence=0.78,
            impact_level="high",
            guard_terms=("sendError", "setStatus", "return", "throw", "verify", "authenticated"),
        ),
        JavaRule(
            rule_id="java_weak_crypto",
            defect_class="weak_crypto",
            skill="java_crypto",
            cwe="CWE-327",
            pattern=re.compile(
                r"\b(?:Cipher\.getInstance\s*\(\s*\"[^\"]*(?:ECB|DES|RC4)[^\"]*\"|MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-1)\"|new\s+SecretKeySpec\s*\([^,]+,\s*\"(?:DES|RC4)\")"
            ),
            sink_label="weak crypto primitive",
            description="使用弱加密算法、模式或摘要，可能导致机密性/完整性不足。",
            root_cause="选择了 ECB/DES/RC4/MD5/SHA-1 等不安全原语或模式。",
            suggested_fix="使用 AES-GCM/ChaCha20-Poly1305、SHA-256+，并采用随机 IV/nonce 和密钥管理。",
            confidence=0.86,
            impact_level="medium",
        ),
        JavaRule(
            rule_id="java_crypto_fixed_iv_or_salt",
            defect_class="crypto_misuse",
            skill="java_crypto",
            cwe="CWE-329",
            pattern=re.compile(
                r"\b(?:IvParameterSpec|GCMParameterSpec|PBEKeySpec)\s*\([^;]*(?:\"[^\"]+\"|new\s+byte\s*\[\s*\d+\s*\]|Arrays\.fill)|SecureRandom\.setSeed\s*\("
            ),
            sink_label="fixed IV/salt/seed",
            description="加密 IV、GCM nonce、KDF salt 或 SecureRandom seed 可能固定或可预测。",
            root_cause="密码学随机材料使用常量或固定种子。",
            suggested_fix="每次加密生成随机 IV/nonce/salt，使用 SecureRandom 且不要手动固定 seed。",
            confidence=0.66,
            impact_level="medium",
            guard_terms=("SecureRandom", "nextBytes", "random"),
        ),
        JavaRule(
            rule_id="java_jwt_verification_misuse",
            defect_class="jwt_misuse",
            skill="java_web_security",
            cwe="CWE-347",
            pattern=re.compile(
                r"\b(?:JWT\.decode|parseClaimsJwt|setSigningKey\s*\(\s*\"|Algorithm\.none\s*\(|noneAlgorithm|withoutVerification\s*\()"
            ),
            sink_label="JWT verification",
            description="JWT 可能只解码不验签、允许 none 算法或硬编码签名密钥。",
            root_cause="令牌签名、算法、过期时间或密钥来源未被安全验证。",
            suggested_fix="强制固定安全算法、验证签名/issuer/audience/exp，并从密钥管理系统读取密钥。",
            confidence=0.68,
            impact_level="high",
            guard_terms=("require", "verify", "withIssuer", "withAudience", "KeyResolver"),
        ),
        JavaRule(
            rule_id="java_manual_close_resource",
            defect_class="resource_leak",
            skill="java_resource_lifecycle",
            cwe="CWE-772",
            pattern=re.compile(
                r"\bnew\s+(?:FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|InputStreamReader|Socket|ServerSocket|Connection|PreparedStatement|ResultSet)\s*\("
            ),
            sink_label="closeable resource allocation",
            description="Closeable/AutoCloseable 资源创建后可能未被 try-with-resources 或 finally 关闭。",
            root_cause="资源生命周期依赖人工 close，当前方法内缺少可证明的关闭路径。",
            suggested_fix="使用 try-with-resources，或在 finally 中关闭所有成功创建的资源。",
            confidence=0.58,
            impact_level="medium",
            guard_terms=("try (", ".close()", "finally", "closeQuietly"),
        ),
        JavaRule(
            rule_id="java_resource_exhaustion_read_all",
            defect_class="resource_exhaustion",
            skill="java_resource_lifecycle",
            cwe="CWE-400",
            pattern=re.compile(
                r"\b(?:readAllBytes|getBytes|IOUtils\.toString|ByteStreams\.toByteArray|copyToByteArray)\s*\("
            ),
            sink_label="unbounded memory read",
            description="一次性读取外部输入可能导致内存耗尽或请求放大。",
            root_cause="缺少大小上限、流式处理或压缩炸弹防护。",
            suggested_fix="限制 Content-Length/文件大小，使用流式处理和解压倍率限制。",
            confidence=0.58,
            impact_level="medium",
            guard_terms=("getSize", "Content-Length", "limit", "BoundedInputStream", "max"),
        ),
        JavaRule(
            rule_id="java_regex_dos",
            defect_class="regex_dos",
            skill="java_web_security",
            cwe="CWE-1333",
            pattern=re.compile(
                r"\b(?:Pattern\.compile|String\.matches|replaceAll|replaceFirst|split)\s*\("
            ),
            sink_label="regex evaluation",
            description="外部可控正则或高复杂度正则可能造成 ReDoS。",
            root_cause="正则表达式或待匹配输入缺少复杂度/长度约束。",
            suggested_fix="固定正则模板，对动态片段使用 Pattern.quote，并限制输入长度或使用安全 regex 引擎。",
            confidence=0.52,
            impact_level="medium",
            guard_terms=("Pattern.quote", "timeout", "length", "matchesSafe"),
        ),
        JavaRule(
            rule_id="java_reflection_dynamic_call",
            defect_class="reflection_injection",
            skill="java_injection",
            cwe="CWE-470",
            pattern=re.compile(
                r"\b(?:Class\.forName|\.getMethod\s*\(|\.getDeclaredMethod\s*\(|\.invoke\s*\(|\.newInstance\s*\()"
            ),
            sink_label="reflection call",
            description="反射类名、方法名或参数若可控，可能绕过预期边界执行危险代码。",
            root_cause="外部输入进入反射解析/调用前缺少固定映射或 allowlist。",
            suggested_fix="用固定命令表/工厂映射替代动态反射，限制可调用类和方法。",
            confidence=0.58,
            impact_level="medium",
            guard_terms=("allowlist", "Map.of", "enum", "switch"),
        ),
        JavaRule(
            rule_id="java_dynamic_class_loading",
            defect_class="dynamic_class_loading",
            skill="java_injection",
            cwe="CWE-470",
            pattern=re.compile(
                r"\b(?:URLClassLoader|defineClass|loadClass|Instrumentation|JarInputStream)\b"
            ),
            sink_label="dynamic class loading",
            description="动态类加载路径或字节码若可控，可能导致插件/代码加载风险。",
            root_cause="外部路径、URL 或字节码进入类加载器前缺少签名、来源和路径校验。",
            suggested_fix="只加载签名可信插件，固定仓库路径，校验 hash/signature 并隔离权限。",
            confidence=0.58,
            impact_level="high",
            guard_terms=("verify", "signature", "checksum", "allowlist"),
        ),
        JavaRule(
            rule_id="java_classpath_resource_traversal",
            defect_class="path_traversal",
            skill="java_web_security",
            cwe="CWE-22",
            pattern=re.compile(
                r"\b(?:getResourceAsStream|getResource|ResourceLoader\.getResource|ServletContext\.getResourceAsStream)\s*\("
            ),
            sink_label="classpath/resource lookup",
            description="类路径或 Web 资源查找可能使用外部输入构造资源路径。",
            root_cause="资源路径进入 classloader/servlet context 前缺少规范化和路径前缀限制。",
            suggested_fix="使用固定资源映射，拒绝 `..`、绝对路径和协议前缀。",
            confidence=0.56,
            impact_level="medium",
            guard_terms=("normalize", "startsWith", "allowlist"),
        ),
        JavaRule(
            rule_id="java_temp_file_risk",
            defect_class="temp_file_risk",
            skill="java_resource_lifecycle",
            cwe="CWE-377",
            pattern=re.compile(
                r"\b(?:File\.createTempFile|Files\.createTempFile|deleteOnExit|new\s+File\s*\(\s*\"/tmp)"
            ),
            sink_label="temporary file handling",
            description="Temporary file handling / 临时文件创建、权限或清理策略可能不安全。",
            root_cause="Temporary file lifecycle 缺少明确清理、权限或目录约束，或依赖 deleteOnExit 长期累积。",
            suggested_fix="使用安全临时目录、限制权限、及时清理，优先使用 DELETE_ON_CLOSE 或 try/finally 删除临时文件。",
            confidence=0.62,
            impact_level="medium",
            guard_terms=(
                "PosixFilePermissions",
                "DELETE_ON_CLOSE",
                "createTempDirectory",
                "delete",
                "finally",
            ),
        ),
        JavaRule(
            rule_id="java_insecure_file_permissions",
            defect_class="insecure_file_permission",
            skill="java_resource_lifecycle",
            cwe="CWE-732",
            pattern=re.compile(
                r"\b(?:setReadable|setWritable|setExecutable)\s*\(\s*true\s*,\s*false\s*\)"
                r"|PosixFilePermissions\.fromString\s*\(\s*\"(?:[rwx-]{6}[rwx]{2,3}|rwxrwxrwx)\"\s*\)"
                r"|Files\.setPosixFilePermissions\s*\(",
                re.I,
            ),
            sink_label="insecure file permission",
            description="文件或目录权限可能被设置为 ownerOnly=false 或 world-readable/writable/executable。",
            root_cause="落盘资源的权限边界过宽，可能允许同机其他用户读取、修改或执行敏感文件。",
            suggested_fix="使用 owner-only 权限，例如 0600/0700，避免 setReadable/setWritable/setExecutable 的 ownerOnly=false，并按最小权限设置 POSIX 权限。",
            confidence=0.76,
            impact_level="medium",
            guard_terms=("OWNER_", "rw-------", "rwx------", "0600", "0700", "ownerOnly"),
        ),
        JavaRule(
            rule_id="java_shared_mutable_static_state",
            defect_class="concurrency_race",
            skill="java_concurrency",
            cwe="CWE-362",
            pattern=re.compile(
                r"\bstatic\s+(?:final\s+)?(?:Map|HashMap|ArrayList|HashSet|SimpleDateFormat|DateFormat|StringBuilder|StringBuffer)\b"
            ),
            sink_label="shared mutable state",
            description="单例/静态共享可变对象可能导致线程安全问题或跨请求状态污染。",
            root_cause="非线程安全对象在多线程 Web 服务中共享，缺少同步或并发容器。",
            suggested_fix="使用不可变对象、ThreadLocal、并发容器，或把状态限制在请求作用域。",
            confidence=0.52,
            impact_level="medium",
            guard_terms=("ConcurrentHashMap", "synchronized", "ThreadLocal", "immutable"),
        ),
        JavaRule(
            rule_id="java_jndi_lookup",
            defect_class="jndi_injection",
            skill="java_injection",
            cwe="CWE-74",
            pattern=re.compile(
                r"\b(?:InitialContext|DirContext|Context)\s*\([^)]*\)|\b(?:InitialContext|DirContext|Context)\s+\w+|\.lookup\s*\("
            ),
            sink_label="JNDI lookup",
            description="JNDI lookup 可能使用外部可控名称，导致远程资源解析或历史 JNDI 注入风险。",
            root_cause="JNDI 名称进入 lookup 前缺少固定前缀、协议限制或 allowlist。",
            suggested_fix="避免用外部输入构造 JNDI 名称；限制协议/前缀并升级依赖和运行时安全配置。",
            confidence=0.74,
            guard_terms=("java:comp/env", "allowlist", "startsWith", "validate"),
        ),
        JavaRule(
            rule_id="java_ldap_search_filter",
            defect_class="ldap_injection",
            skill="java_injection",
            cwe="CWE-90",
            pattern=re.compile(r"\b(?:DirContext|LdapContext)\b|\.search\s*\("),
            sink_label="LDAP search/filter",
            description="LDAP 查询过滤器可能拼接外部输入，存在 LDAP 注入风险。",
            root_cause="用户输入进入 LDAP filter/base DN 前缺少 RFC 4515 转义或参数化构造。",
            suggested_fix="对 filter 特殊字符做 LDAP 转义，避免字符串拼接，并限制 base DN。",
            confidence=0.7,
            guard_terms=("escapeLDAP", "encodeForLDAP", "LdapEncoder", "filterEncode", "allowlist"),
        ),
        JavaRule(
            rule_id="java_expression_or_script_eval",
            defect_class="code_injection",
            skill="java_injection",
            cwe="CWE-94",
            pattern=re.compile(
                r"\b(?:ScriptEngine|GroovyShell|ExpressionParser|SpelExpressionParser|MVEL|JexlEngine|Jinjava)\b|\.eval\s*\(|\.parseExpression\s*\(|\.createExpression\s*\("
            ),
            sink_label="expression/script evaluation",
            description="表达式或脚本解释器可能执行外部可控表达式。",
            root_cause="动态表达式进入解释/执行汇点前缺少固定模板、沙箱或 allowlist。",
            suggested_fix="避免解释用户输入；使用固定表达式模板、禁用危险对象访问并启用沙箱。",
            confidence=0.78,
        ),
        JavaRule(
            rule_id="java_open_redirect",
            defect_class="open_redirect",
            skill="java_web_security",
            cwe="CWE-601",
            pattern=re.compile(
                r"\b(?:sendRedirect|RedirectView)\s*\(|return\s+\"redirect:|ModelAndView\s*\(\s*\"redirect:"
            ),
            sink_label="HTTP redirect",
            description="重定向目标可能由外部输入控制，造成开放重定向或钓鱼跳转。",
            root_cause="跳转 URL/路径进入 redirect 汇点前缺少同源、相对路径或 allowlist 约束。",
            suggested_fix="仅允许相对路径或固定 allowlist 域名，拒绝 scheme-relative 和外部 URL。",
            confidence=0.68,
            impact_level="medium",
            guard_terms=("isLocalUrl", "allowlist", 'startsWith("/")', "URI", "getHost"),
        ),
        JavaRule(
            rule_id="java_xpath_expression_concat",
            defect_class="xpath_injection",
            skill="java_injection",
            cwe="CWE-643",
            pattern=re.compile(
                r"\bXPathFactory\b|\.compile\s*\([^)]*\+|\.evaluate\s*\([^)]*\+", re.I
            ),
            sink_label="XPath expression evaluation",
            description="XPath 表达式可能由外部输入拼接构造，导致 XPath 注入。",
            root_cause="请求参数进入 XPath 表达式字符串后直接 compile/evaluate，缺少变量绑定或严格 allowlist。",
            suggested_fix="使用 XPathVariableResolver/固定表达式模板，或对可变部分做严格 allowlist。",
            confidence=0.74,
            guard_terms=("XPathVariableResolver", "allowlist", "escapeXPath", "sanitize"),
        ),
        JavaRule(
            rule_id="java_druid_monitor_exposure",
            defect_class="sensitive_info_exposure",
            skill="java_web_security",
            cwe="CWE-200",
            pattern=re.compile(
                r"\bStatViewServlet\b|/druid/\*|DruidStatViewServlet|management\.endpoints\.web\.exposure|springdoc|swagger-ui",
                re.I,
            ),
            sink_label="public management/monitor endpoint",
            description="Druid、Actuator 或 Swagger 等管理/文档入口可能公开暴露敏感运行信息。",
            root_cause="管理或监控 servlet/endpoint 注册后缺少登录、IP allowlist 或环境隔离。",
            suggested_fix="关闭生产暴露，或为管理端点增加认证、IP allowlist 和最小化 exposure include。",
            confidence=0.72,
            guard_terms=(
                "loginUsername",
                "loginPassword",
                "allow",
                "deny",
                "hasRole",
                "management.server.port",
            ),
        ),
        JavaRule(
            rule_id="java_zip_entry_path_traversal",
            defect_class="path_traversal",
            skill="java_web_security",
            cwe="CWE-22",
            pattern=re.compile(
                r"\b(?:ZipInputStream|ZipFile)\b|\.getNextEntry\s*\(|\.entries\s*\(\)|\.getName\s*\(\)"
            ),
            sink_label="archive entry path",
            description="压缩包条目名可能包含 `../` 或绝对路径，解压时造成 Zip Slip。",
            root_cause="归档条目名写入文件系统前缺少 normalize 后的目标根目录校验。",
            suggested_fix="对 entry name resolve/normalize 后验证仍位于目标目录下，并拒绝绝对路径。",
            confidence=0.64,
            impact_level="medium",
            guard_terms=("normalize", "startsWith", "toRealPath", "getCanonicalPath"),
        ),
        JavaRule(
            rule_id="java_weak_random_security",
            defect_class="weak_random",
            skill="java_crypto",
            cwe="CWE-338",
            pattern=re.compile(
                r"\b(?:new\s+Random\s*\(|Math\.random\s*\(|ThreadLocalRandom\.current\s*\()"
            ),
            sink_label="predictable random",
            description="安全敏感 token、密钥或验证码若使用可预测随机数会降低安全性。",
            root_cause="使用非密码学安全随机数生成安全敏感值。",
            suggested_fix="安全敏感随机值使用 `SecureRandom`，并避免固定种子。",
            confidence=0.58,
            impact_level="medium",
            guard_terms=("SecureRandom", "nonce", "salt"),
        ),
        JavaRule(
            rule_id="java_tls_verification_disabled",
            defect_class="insecure_tls",
            skill="java_web_security",
            cwe="CWE-295",
            pattern=re.compile(
                r"\b(?:TrustAll|X509TrustManager|HostnameVerifier|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier)\b|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"
            ),
            sink_label="TLS verification bypass",
            description="TLS 证书或主机名校验可能被禁用。",
            root_cause="自定义 TrustManager/HostnameVerifier 接受任意证书或主机名。",
            suggested_fix="使用默认 TLS 校验，移除 trust-all verifier，并正确配置受信 CA。",
            confidence=0.74,
            impact_level="high",
        ),
        JavaRule(
            rule_id="java_hardcoded_secret",
            defect_class="secret_exposure",
            skill="java_web_security",
            cwe="CWE-798",
            pattern=re.compile(
                r"\b(?:password|passwd|secret|api[-_]?key|apikey|access[-_]?key|token|credential)\b"
                r"\s*[:=]\s*(?:\"[^\"]{8,}\"|'[^']{8,}'|[A-Za-z0-9_./+=:-]{8,})",
                re.I,
            ),
            sink_label="hardcoded secret",
            description="源码或配置文件中可能硬编码 password、token、secret 或访问密钥。",
            root_cause="敏感凭据直接写入代码或 application properties/yaml 配置，容易进入仓库、镜像或日志上下文。",
            suggested_fix="改用密钥管理服务或环境变量，并轮换已泄露凭据。",
            confidence=0.74,
            impact_level="medium",
            guard_terms=("System.getenv", "getenv", "Vault", "SecretManager"),
        ),
        JavaRule(
            rule_id="java_reflected_xss_response_body",
            defect_class="xss",
            skill="java_web_security",
            cwe="CWE-79",
            pattern=re.compile(
                r"\breturn\s+(?:payload|content|html|input|name|value|param)\s*;|ResponseEntity\.ok\s*\([^)]*(?:payload|content|html|input|param)",
                re.I,
            ),
            sink_label="reflected response body",
            description="Controller 直接把请求参数返回到响应体，前端或浏览器 HTML 解析时可能触发反射型 XSS。",
            root_cause="未对外部输入进行 HTML/JS 上下文转义即返回给客户端。",
            suggested_fix="按输出上下文进行 HTML/JS/URL 转义，或返回结构化 JSON 并确保前端安全渲染。",
            confidence=0.78,
            impact_level="medium",
            guard_terms=("escapeHtml", "HtmlUtils.htmlEscape", "Encode.forHtml", "sanitize"),
        ),
        JavaRule(
            rule_id="java_stored_xss_persistent_content",
            defect_class="xss",
            skill="java_web_security",
            cwe="CWE-79",
            pattern=re.compile(
                r"\b(?:insertOne|save|insert|update|insertSelective|saveAndFlush)\s*\([^;]*(?:payload|content|comment|message|User-Agent|ua|getHeader)[^;]*\)",
                re.I,
            ),
            sink_label="stored XSS persistence",
            description="用户输入或 User-Agent 被持久化，后续页面若不安全渲染会触发存储型 XSS。",
            root_cause="持久化前缺少内容安全策略和输出阶段上下文转义约束。",
            suggested_fix="保存前做安全策略校验，并在展示端使用转义输出，禁止 th:utext/innerHTML 渲染不可信内容。",
            confidence=0.76,
            impact_level="medium",
            guard_terms=("escapeHtml", "sanitize", "Jsoup.clean", "AntiSamy", "Encode.forHtml"),
        ),
        JavaRule(
            rule_id="java_template_utext_xss",
            defect_class="xss",
            skill="java_web_security",
            cwe="CWE-79",
            pattern=re.compile(
                r"\bmodel\.addAttribute\s*\(\s*\"(?:html|content|templateContent|message|comment)\"\s*,\s*(?:payload|content|html|input|param|message|comment)\s*\)|th:utext",
                re.I,
            ),
            sink_label="template unescaped HTML model attribute",
            description="用户输入进入模板 HTML 模型字段，若模板使用 th:utext 等不转义输出会触发 XSS。",
            root_cause="外部输入作为 HTML 内容进入服务端模板模型，缺少转义或安全 HTML 清洗。",
            suggested_fix="使用 th:text/转义输出；如必须渲染 HTML，先通过可信 allowlist 清洗。",
            confidence=0.78,
            impact_level="medium",
            guard_terms=("escapeHtml", "sanitize", "Jsoup.clean", "th:text"),
        ),
    )

    _RESOURCE_BY_CLASS = {
        "sql_injection": "database",
        "jpa_injection": "database",
        "nosql_injection": "database",
        "command_injection": "process",
        "path_traversal": "file",
        "file_upload": "file_upload",
        "ssrf": "network",
        "unsafe_deserialization": "serialization",
        "xxe": "xml_parser",
        "template_injection": "template_engine",
        "sensitive_log": "logging",
        "header_injection": "http_header",
        "insecure_cookie": "cookie",
        "cors_misconfiguration": "cors",
        "authz_bypass": "authorization",
        "weak_crypto": "crypto",
        "crypto_misuse": "crypto",
        "jwt_misuse": "jwt",
        "weak_random": "crypto",
        "insecure_tls": "network",
        "jndi_injection": "naming_directory",
        "ldap_injection": "directory",
        "code_injection": "interpreter",
        "open_redirect": "http_redirect",
        "secret_exposure": "secret",
        "resource_leak": "resource_lifecycle",
        "resource_exhaustion": "resource_lifecycle",
        "regex_dos": "regex",
        "reflection_injection": "reflection",
        "dynamic_class_loading": "class_loading",
        "temp_file_risk": "file",
        "insecure_file_permission": "file_permission",
        "concurrency_race": "shared_state",
        "xss": "browser_output",
    }

    def generate_issues(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
        annotations: Optional[Iterable[Any]] = None,
    ) -> List[Dict[str, Any]]:
        lines = self._parse_lines(code)
        lines = self._merge_annotation_lines(lines, annotations)
        if not lines:
            return []
        allowed = set(allowed_skills) if allowed_skills is not None else None
        issues: List[Dict[str, Any]] = []
        for line in lines:
            if not line.text:
                continue
            for rule in self._RULES:
                should_emit, descriptor = resolve_emitter_descriptor(
                    self.rule_policy,
                    rule.rule_id,
                    defect_class=rule.defect_class,
                    language="java",
                )
                if not should_emit:
                    continue
                if (
                    allowed is not None
                    and descriptor is not None
                    and descriptor.skill not in allowed
                ):
                    continue
                if not rule.pattern.search(line.text):
                    continue
                if not self._rule_applies_to_line(rule, file_path, lines, line):
                    continue
                negative = self._guard_evidence(lines, line.index, rule)
                issues.append(
                    self._issue_for_rule(
                        func_name,
                        file_path,
                        lines,
                        line,
                        rule,
                        descriptor,
                        negative,
                    )
                )

        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            deduped.setdefault(str(issue.get("dedup_key") or issue["id"]), issue)
        return list(deduped.values())

    def issue_to_ticket(self, issue: Dict[str, Any]) -> "CandidateTicket":
        from ...orchestration.candidates import CandidateTicket

        defect_class = str(issue.get("defect_class") or "unknown")
        evidence = dict(issue.get("evidence_pack") or {})
        rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
        descriptor = resolve_rule_descriptor(
            self.rule_policy,
            rule_id,
            defect_class=defect_class,
            language="java",
        )
        return CandidateTicket(
            id=str(issue.get("candidate_id") or issue.get("id")),
            skill=str(
                issue.get("skill")
                or (descriptor.skill if descriptor is not None else "java_web_security")
            ),
            task=(
                f"Verify Java local-rule {defect_class} candidate. Confirm source "
                "controllability, sink reachability, sanitizers/guards, framework entry "
                "exposure, and exploitability; reject if proof is missing."
            ),
            trigger=str(issue.get("rule") or defect_class),
            line=self._line_from_location(str(issue.get("location") or "")),
            context_slice=str(issue.get("code_snippet") or ""),
            priority_score=self._priority_for_issue(issue),
            priority_reasons=[
                str(issue.get("candidate_source") or "java_local_rule"),
                defect_class,
                f"rule_confidence={issue.get('rule_confidence', issue.get('confidence', 0.5))}",
            ],
            origin=str(issue.get("source") or issue.get("location") or ""),
            sink=str(issue.get("sink") or issue.get("location") or ""),
            resource_kind=self._RESOURCE_BY_CLASS.get(defect_class, "unknown"),
            source=str(issue.get("candidate_source") or "java_local_rule"),
            evidence=evidence,
        )

    def _issue_for_rule(
        self,
        func_name: str,
        file_path: str,
        lines: List[JavaLine],
        line: JavaLine,
        rule: JavaRule,
        descriptor: Optional[ResolvedRuleDescriptor],
        negative: List[str],
    ) -> Dict[str, Any]:
        cwe = descriptor.cwe if descriptor is not None else ""
        skill = descriptor.skill if descriptor is not None else ""
        sink = self._sink_expression(line.text, rule)
        candidate_id = self._candidate_id(
            func_name, file_path, rule.defect_class, line.number, sink
        )
        location = f"{file_path}:{line.number}" if file_path else f"{func_name}:{line.number}"
        positive = [
            f"Java local rule `{rule.rule_id}` matched `{sink}` in `{func_name}` at {location}.",
            f"Matched source line: {line.text}",
        ]
        guard_status = "needs_validation" if negative else "insufficient_or_absent"
        evidence_pack: Dict[str, Any] = {
            "candidate_id": candidate_id,
            "candidate_source": "java_local_rule",
            "defect_class": rule.defect_class,
            "rule": rule.rule_id,
            "rule_id": descriptor.rule_id if descriptor is not None else rule.rule_id,
            "cwe": cwe,
            "skill": skill,
            "rule_confidence": rule.confidence,
            "language": "java",
            "source": {
                "expression": "method parameters/request/message/file input or derived value",
                "line": line.number,
                "file": file_path,
            },
            "sink": {
                "operation": sink,
                "line": line.number,
                "file": file_path,
            },
            "path": {
                "function": func_name,
                "complete_in_function": self._rule_has_local_complete_evidence(rule),
                "guard_status": guard_status,
                "path_constraints": [
                    "local Java rule is syntactic and path-insensitive",
                    "validator must confirm source-to-sink flow and framework reachability",
                ],
            },
            "positive_evidence": positive,
            "negative_evidence": negative,
            "evidence_refs": [],
        }
        if rule.defect_class in {"secret_exposure", "temp_file_risk", "authz_bypass"}:
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["path_constraints"] = [
                    f"deterministic Java rule evidence for {rule.defect_class}",
                    "validator must confirm exposure and contextual exploitability",
                ]
            if rule.defect_class == "secret_exposure":
                evidence_pack["source"] = {
                    "expression": "hardcoded configuration or source literal",
                    "line": line.number,
                    "file": file_path,
                    "kind": "java_project_secret_literal",
                }
            elif rule.defect_class == "temp_file_risk":
                evidence_pack["source"] = {
                    "expression": "externally triggerable method or repeated local execution",
                    "line": line.number,
                    "file": file_path,
                    "kind": "java_temporary_file_allocation",
                }
            elif rule.defect_class == "authz_bypass":
                evidence_pack["source"] = {
                    "expression": "framework route or public method invoking sensitive state change",
                    "line": line.number,
                    "file": file_path,
                    "kind": "java_sensitive_operation",
                }
        if rule.rule_id == "java_filter_unconditional_chain":
            source_line = self._nearest_filter_auth_context_line(lines, line.index) or line.number
            evidence_pack["source"] = {
                "expression": "Servlet request authentication context, Authorization/Bearer token header, or missing credentials",
                "line": source_line,
                "file": file_path,
                "kind": "java_servlet_filter_authentication_boundary",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_servlet_filter_chain_continuation",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java servlet filter rule evidence",
                    "same method observes authentication header/token context and continues FilterChain",
                ]
        elif rule.rule_id == "java_classpath_resource_traversal":
            evidence_pack["source"] = {
                "expression": "resource name parameter or derived classpath resource path",
                "line": line.number,
                "file": file_path,
                "kind": "java_public_api_parameter",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_classpath_resource_lookup",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java classpath resource lookup rule evidence",
                    "resource lookup receives a method parameter or derived value without path prefix validation",
                ]
        elif rule.rule_id == "java_cors_wildcard":
            evidence_pack["source"] = {
                "expression": "Spring CORS policy annotation or configuration",
                "line": line.number,
                "file": file_path,
                "kind": "java_framework_security_policy",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_cors_policy",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java CORS wildcard rule evidence",
                    "Spring CORS annotation/configuration allows wildcard origins",
                ]
        elif rule.rule_id == "java_spring_security_permit_all":
            evidence_pack["source"] = {
                "expression": "Spring Security HTTP authorization configuration",
                "line": line.number,
                "file": file_path,
                "kind": "java_framework_security_policy",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_spring_security_permit_all",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java Spring Security rule evidence",
                    "security filter chain disables or broadly permits protected routes",
                ]
        elif rule.rule_id == "java_mybatis_dollar_substitution":
            evidence_pack["source"] = {
                "expression": "MyBatis mapper method parameter or request-derived value",
                "line": line.number,
                "file": file_path,
                "kind": "mybatis_annotation_or_xml_mapper_parameter",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "mybatis_text_substitution",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java MyBatis textual substitution evidence",
                    "`${...}` injects raw text into SQL and must be allowlisted or replaced with `#{...}`",
                ]
        elif rule.rule_id == "java_shared_mutable_static_state":
            evidence_pack["source"] = {
                "expression": "static mutable field declaration",
                "line": line.number,
                "file": file_path,
                "kind": "java_shared_static_mutable_field",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_shared_static_state",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java shared mutable static field evidence",
                    "validator must confirm the field is reached from request, listener, scheduler, or public API code",
                ]
        elif rule.rule_id in {"java_jdbc_concatenated_sql", "java_jdbc_fake_prepared_statement"}:
            source_line = (
                self._nearest_java_parameter_or_sql_assignment_line(lines, line.index)
                or line.number
            )
            evidence_pack["source"] = {
                "expression": "request parameter or method parameter concatenated into SQL string",
                "line": source_line,
                "file": file_path,
                "kind": "java_jdbc_sql_construction",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_jdbc_sql_execution_or_preparation",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java JDBC SQL construction evidence",
                    "SQL variable is constructed through string concatenation before JDBC/JdbcTemplate execution or preparation",
                ]
        elif rule.rule_id == "java_xxe_factory":
            parse_line = self._nearest_xml_parse_line(lines, line.index) or line.number
            evidence_pack["source"] = {
                "expression": "request XML payload or method parameter passed to parser",
                "line": parse_line,
                "file": file_path,
                "kind": "java_xml_untrusted_input",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_xml_parser_factory_or_reader",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java XML parser rule evidence",
                    "method creates XML parser/reader without nearby secure external entity controls",
                ]
        elif rule.rule_id == "java_xmldecoder_readobject":
            read_line = self._nearest_xml_decoder_read_line(lines, line.index) or line.number
            evidence_pack["source"] = {
                "expression": "request-controlled XML payload used to build XMLDecoder input stream",
                "line": line.number,
                "file": file_path,
                "kind": "java_xmldecoder_input",
            }
            evidence_pack["sink"] = {
                "operation": "XMLDecoder.readObject()",
                "line": read_line,
                "file": file_path,
                "kind": "java_xmldecoder_readobject",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java XMLDecoder rule evidence",
                    "XMLDecoder is created over method-local payload-derived XML and readObject is invoked",
                ]
        elif rule.rule_id in {
            "java_reflected_xss_response_body",
            "java_stored_xss_persistent_content",
            "java_template_utext_xss",
        }:
            source_line = (
                self._nearest_java_parameter_or_request_line(lines, line.index) or line.number
            )
            evidence_pack["source"] = {
                "expression": "request parameter/header/body carrying HTML/script-capable content",
                "line": source_line,
                "file": file_path,
                "kind": "java_web_untrusted_output_source",
            }
            evidence_pack["sink"] = {
                "operation": sink,
                "line": line.number,
                "file": file_path,
                "kind": "java_web_xss_sink",
            }
            if isinstance(evidence_pack.get("path"), dict):
                evidence_pack["path"]["complete_in_function"] = True
                evidence_pack["path"]["path_constraints"] = [
                    "deterministic Java XSS sink rule evidence",
                    "request-derived value reaches response, persistence, or unescaped template model without local escaping",
                ]
        reasoning = self._reasoning(
            rule,
            cwe,
            func_name,
            location,
            sink,
            positive,
            negative,
        )
        dedup_key = "|".join(
            [
                rule.defect_class,
                file_path.replace("\\", "/").lower(),
                str(line.number),
                self._normalize_sink_key(sink),
            ]
        )
        return {
            "id": candidate_id,
            "candidate_id": candidate_id,
            "function": func_name,
            "location": location,
            "category": rule.defect_class,
            "subcategory": rule.defect_class,
            "defect_class": rule.defect_class,
            "finding_kind": "java_rule_candidate",
            "candidate_source": "java_local_rule",
            "evidence_checker": "java_local_rule_checker",
            "rule": rule.rule_id,
            "rule_id": descriptor.rule_id if descriptor is not None else rule.rule_id,
            "cwe": cwe,
            "skill": skill,
            "description": rule.description,
            "root_cause": rule.root_cause,
            "suggested_fix": rule.suggested_fix,
            "confidence": rule.confidence,
            "rule_confidence": rule.confidence,
            "impact_level": rule.impact_level,
            "reasoning": reasoning,
            "code_snippet": self._context(lines, line.index - 5, line.index + 8),
            "source": "method parameters/request/message/file input or derived value",
            "sink": sink,
            "dedup_key": dedup_key,
            "positive_evidence": positive,
            "negative_evidence": negative,
            "evidence_pack": evidence_pack,
            "evidence_refs": [],
        }

    def _parse_lines(self, code: str) -> List[JavaLine]:
        result: List[JavaLine] = []
        for idx, raw in enumerate(str(code or "").splitlines(), start=1):
            match = self._LINE_RE.match(raw)
            if match:
                number = int(match.group(1))
                text = match.group(2).strip()
            else:
                number = idx
                text = raw.strip()
            result.append(JavaLine(number=number, raw=raw, text=text, index=len(result)))
        return result

    def _merge_annotation_lines(
        self,
        lines: List[JavaLine],
        annotations: Optional[Iterable[Any]],
    ) -> List[JavaLine]:
        if not annotations:
            return lines
        existing = {(line.number, line.text) for line in lines}
        fallback_line = lines[0].number if lines else 1
        merged = list(lines)
        for number, text in self._annotation_entries(annotations, fallback_line):
            key = (number, text)
            if not text or key in existing:
                continue
            existing.add(key)
            merged.append(JavaLine(number=number, raw=text, text=text, index=0))
        merged.sort(key=lambda item: (item.number, item.text))
        return [
            JavaLine(number=line.number, raw=line.raw, text=line.text, index=index)
            for index, line in enumerate(merged)
        ]

    @classmethod
    def _annotation_entries(
        cls,
        values: Iterable[Any],
        fallback_line: int,
    ) -> List[tuple[int, str]]:
        entries: List[tuple[int, str]] = []

        def visit(value: Any) -> None:
            if isinstance(value, str):
                text = value.strip()
                if text:
                    entries.append((fallback_line, text))
                return
            if isinstance(value, dict):
                code = str(value.get("code") or "").strip()
                if code.startswith("@"):
                    line = value.get("lineNumber", value.get("line", fallback_line))
                    try:
                        number = int(line) if line is not None else fallback_line
                    except (TypeError, ValueError):
                        number = fallback_line
                    entries.append((number if number > 0 else fallback_line, code))
                nested = value.get("annotations")
                if isinstance(nested, (list, tuple)):
                    for item in nested:
                        visit(item)
                return
            if isinstance(value, (list, tuple)):
                for item in value:
                    visit(item)

        if isinstance(values, (str, dict)):
            visit(values)
        else:
            visit(list(values))
        return entries

    def _guard_evidence(self, lines: List[JavaLine], idx: int, rule: JavaRule) -> List[str]:
        terms = tuple(rule.guard_terms or ()) + self._DEFAULT_GUARD_TERMS
        window = " ".join(line.text for line in lines[max(0, idx - 6) : min(len(lines), idx + 4)])
        hits = sorted({term for term in terms if term and term in window})
        if not hits:
            return []
        return [
            "Nearby potential guard/sanitizer/resource-management terms found: "
            + ", ".join(hits[:8])
            + "; validator must prove they dominate the sink and cover attacker-controlled input."
        ]

    @staticmethod
    def _nearest_filter_auth_context_line(lines: List[JavaLine], idx: int) -> int:
        window = list(lines[max(0, idx - 10) : idx + 1])
        for item in reversed(window):
            text = item.text.lower()
            if any(token in text for token in ("authorization", "getheader")):
                return item.number
        for item in reversed(window):
            text = item.text.lower()
            if "bearer" in text:
                return item.number
        for item in reversed(window):
            text = item.text.lower()
            if any(token in text for token in ("token", "jwt")):
                return item.number
        return 0

    @staticmethod
    def _nearest_java_parameter_or_request_line(lines: List[JavaLine], idx: int) -> int:
        window = list(lines[max(0, idx - 12) : idx + 1])
        for item in reversed(window):
            text = item.text.lower()
            if any(
                token in text
                for token in (
                    "@requestparam",
                    "@requestbody",
                    "getheader",
                    "getparameter",
                    "payload",
                    "content",
                )
            ):
                return item.number
        return 0

    @staticmethod
    def _nearest_java_parameter_or_sql_assignment_line(lines: List[JavaLine], idx: int) -> int:
        window = list(lines[max(0, idx - 12) : idx + 1])
        for item in reversed(window):
            text = item.text.lower()
            if "sql" in text and "=" in text and "+" in text:
                return item.number
        for item in reversed(window):
            text = item.text.lower()
            if any(token in text for token in ("@requestparam", "@requestbody", "getparameter")):
                return item.number
        return 0

    @staticmethod
    def _nearest_xml_parse_line(lines: List[JavaLine], idx: int) -> int:
        window = list(lines[idx : min(len(lines), idx + 12)])
        for item in window:
            text = item.text.lower()
            if ".parse(" in text or "inputsource" in text:
                return item.number
        return 0

    @staticmethod
    def _nearest_xml_decoder_read_line(lines: List[JavaLine], idx: int) -> int:
        window = list(lines[idx : min(len(lines), idx + 8)])
        for item in window:
            if "readObject" in item.text:
                return item.number
        return 0

    @staticmethod
    def _rule_applies_to_line(
        rule: JavaRule,
        file_path: str,
        lines: List[JavaLine],
        line: JavaLine,
    ) -> bool:
        if rule.rule_id == "java_filter_unconditional_chain":
            context = " ".join(item.text for item in lines).lower()
            window = " ".join(
                item.text
                for item in lines[max(0, line.index - 8) : min(len(lines), line.index + 3)]
            ).lower()
            return (
                "dofilter" in context
                and "filterchain" in context
                and any(token in window for token in ("authorization", "bearer", "token", "jw"))
                and "chain.dofilter" in line.text.lower()
            )
        if rule.rule_id == "java_jdbc_concatenated_sql":
            lowered = line.text.lower()
            return "+" in line.text and any(
                keyword in lowered for keyword in ("select", "insert", "update", "delete")
            )
        if rule.rule_id == "java_jdbc_fake_prepared_statement":
            window = " ".join(
                item.text
                for item in lines[max(0, line.index - 8) : min(len(lines), line.index + 5)]
            ).lower()
            return (
                "preparestatement" in line.text.lower()
                and any(keyword in window for keyword in ("select", "insert", "update", "delete"))
                and "+" in window
                and any(
                    token in window
                    for token in (
                        "executeupdate(sql",
                        "executequery(sql",
                        ".execute(sql",
                        "preparestatement(sql",
                    )
                )
            )
        if rule.rule_id == "java_xxe_factory":
            window = " ".join(
                item.text
                for item in lines[max(0, line.index - 4) : min(len(lines), line.index + 12)]
            ).lower()
            if any(token.lower() in window for token in rule.guard_terms):
                return False
            return True
        if rule.rule_id == "java_xmldecoder_readobject":
            window = " ".join(
                item.text
                for item in lines[max(0, line.index - 8) : min(len(lines), line.index + 8)]
            ).lower()
            return "readobject" in window or "payload" in window
        if rule.rule_id == "java_reflected_xss_response_body":
            context = " ".join(
                item.text for item in lines[max(0, line.index - 12) : line.index + 1]
            ).lower()
            web_response_context = (
                "@responsebody" in context
                or "@restcontroller"
                in " ".join(item.text for item in lines[: min(len(lines), 30)]).lower()
                or "controller" in file_path.lower()
            )
            return web_response_context and any(
                token in context for token in ("payload", "content", "requestparam")
            )
        if rule.rule_id == "java_stored_xss_persistent_content":
            context = " ".join(
                item.text for item in lines[max(0, line.index - 10) : line.index + 1]
            ).lower()
            return any(
                token in context
                for token in ("payload", "user-agent", "getheader", "@requestparam")
            )
        if rule.rule_id == "java_template_utext_xss":
            context = " ".join(
                item.text
                for item in lines[max(0, line.index - 10) : min(len(lines), line.index + 8)]
            ).lower()
            return "payload" in context and ("html" in context or "utext" in context)
        if rule.rule_id == "java_open_redirect":
            context = " ".join(
                item.text for item in lines[max(0, line.index - 10) : line.index + 1]
            ).lower()
            return any(
                token in context
                for token in (
                    "@requestparam",
                    "getparameter",
                    "url",
                    "redirect",
                    "returnurl",
                    "target",
                )
            )
        if rule.rule_id == "java_xpath_expression_concat":
            window = " ".join(
                item.text
                for item in lines[max(0, line.index - 8) : min(len(lines), line.index + 8)]
            ).lower()
            return (
                "xpath" in window
                and "+" in window
                and any(
                    token in window
                    for token in (
                        "@requestparam",
                        "getparameter",
                        "username",
                        "password",
                        "payload",
                    )
                )
            )
        if rule.rule_id == "java_druid_monitor_exposure":
            window = " ".join(
                item.text
                for item in lines[max(0, line.index - 8) : min(len(lines), line.index + 8)]
            ).lower()
            return any(
                token in window
                for token in ("statviewservlet", "/druid", "actuator", "swagger", "springdoc")
            )
        if rule.rule_id == "java_missing_object_authorization":
            context = " ".join(
                item.text
                for item in lines[max(0, line.index - 12) : min(len(lines), line.index + 4)]
            ).lower()
            if any(token.lower() in context for token in rule.guard_terms):
                return False
            return any(
                token in context
                for token in (
                    "@requestparam",
                    "@pathvariable",
                    "getparameter",
                    "username",
                    "userid",
                    "orderid",
                    "accountid",
                    " id",
                )
            )
        if rule.rule_id != "java_mybatis_dollar_substitution":
            if rule.rule_id == "java_ldap_search_filter":
                window = " ".join(
                    item.text
                    for item in lines[max(0, line.index - 4) : min(len(lines), line.index + 5)]
                ).lower()
                if any(
                    token in window
                    for token in (
                        "@select",
                        "@insert",
                        "@update",
                        "@delete",
                        "select ",
                        " from ",
                        "${",
                    )
                ):
                    return False
                return any(
                    token in window
                    for token in (
                        "dircontext",
                        "ldapcontext",
                        "ldap",
                        ".search(",
                        "searchcontrols",
                    )
                )
            return True
        suffix = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        if suffix not in {"java", "xml"}:
            return False
        window = " ".join(
            item.text for item in lines[max(0, line.index - 3) : min(len(lines), line.index + 4)]
        ).lower()
        return any(
            token in window
            for token in (
                "@select",
                "@insert",
                "@update",
                "@delete",
                "<select",
                "<insert",
                "<update",
                "<delete",
                " select ",
                " insert ",
                " update ",
                " delete ",
                " from ",
                " order by ",
                " where ",
                " values ",
            )
        )

    @staticmethod
    def _sink_expression(text: str, rule: JavaRule) -> str:
        match = rule.pattern.search(text)
        if not match:
            return rule.sink_label
        start = match.start()
        return text[start : min(len(text), start + 180)].strip()

    @staticmethod
    def _candidate_id(
        func_name: str, file_path: str, defect_class: str, line: int, sink: str
    ) -> str:
        digest = hashlib.sha1(
            f"java:{file_path}:{func_name}:{defect_class}:{line}:{sink}".encode("utf-8")
        ).hexdigest()[:10]
        prefix = re.sub(r"[^A-Za-z0-9]+", "_", defect_class).upper()
        return f"JAVA_RULE_{prefix}_{line}_{digest}"

    @staticmethod
    def _context(lines: List[JavaLine], start: int, end: int) -> str:
        start = max(0, start)
        end = min(len(lines), end)
        return "\n".join(f"{line.number} | {line.text}" for line in lines[start:end])

    @staticmethod
    def _reasoning(
        rule: JavaRule,
        cwe: str,
        func_name: str,
        location: str,
        sink: str,
        positive: List[str],
        negative: List[str],
    ) -> str:
        lines = [
            f"Java 本地规则 `{rule.rule_id}` 在 `{func_name}` 的 `{location}` 命中 `{rule.defect_class}`（{cwe}）候选。",
            f"问题判断：{rule.description}",
            f"汇点/操作：`{sink}`。",
            "保护状态："
            + (
                "存在附近潜在保护，需要验证支配关系。"
                if negative
                else "当前方法片段未看到足够的保护或安全配置。"
            ),
            "关键证据：",
        ]
        lines.extend(f"- {item}" for item in positive[:4])
        if negative:
            lines.append("需要复核的反向证据：")
            lines.extend(f"- {item}" for item in negative[:3])
        lines.append(f"根因：{rule.root_cause}")
        lines.append(f"建议：{rule.suggested_fix}")
        return "\n".join(lines)

    @staticmethod
    def _line_from_location(location: str) -> int:
        match = re.search(r":(\d+)(?::|$)", location)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _normalize_sink_key(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip().lower())[:120]

    @staticmethod
    def _rule_has_local_complete_evidence(rule: JavaRule) -> bool:
        return rule.defect_class in {
            "authz_bypass",
            "secret_exposure",
            "temp_file_risk",
            "insecure_file_permission",
            "cors_misconfiguration",
            "sql_injection",
            "xxe",
            "xss",
            "unsafe_deserialization",
            "insecure_cookie",
            "weak_crypto",
            "crypto_misuse",
            "weak_random",
        }

    @staticmethod
    def _priority_for_issue(issue: Dict[str, Any]) -> int:
        try:
            score = float(issue.get("rule_confidence", issue.get("confidence", 0.5)))
        except (TypeError, ValueError):
            score = 0.5
        severity = str(issue.get("impact_level") or "").lower()
        bonus = {"critical": 18, "high": 12, "medium": 6, "low": 0}.get(severity, 3)
        return max(1, min(100, int(score * 80) + bonus))

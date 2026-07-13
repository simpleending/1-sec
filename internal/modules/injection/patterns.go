package injection

import (
	"regexp"

	"github.com/1sec-project/1sec/internal/core"
)

func compilePatterns() []Pattern {
	patterns := []Pattern{
		// SQL Injection patterns
		{Name: "sqli_union", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\bunion\b\s+(all\s+)?select\b)`)},
		{Name: "sqli_or_true", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\bor\b\s+[\d'"]+=\s*[\d'"]+|'\s*or\s*'[^']*'\s*=\s*'[^']*')`)},
		{Name: "sqli_comment", Category: "sqli", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile(`(?i)(--|#|/\*.*?\*/|;)\s*(drop|alter|delete|update|insert|create|exec|execute)\b`)},
		{Name: "sqli_stacked", Category: "sqli", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i);\s*(drop|alter|truncate|delete\s+from|update\s+\w+\s+set|insert\s+into|create|exec|execute)\b`)},
		{Name: "sqli_sleep", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay\s+')`)},
		{Name: "sqli_extract", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(extractvalue|updatexml|load_file|into\s+(out|dump)file)\s*\(`)},
		{Name: "sqli_information_schema", Category: "sqli", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(information_schema|sys\.objects|sysobjects|syscolumns|pg_catalog)`)},
		{Name: "sqli_hex_encode", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(0x[0-9a-f]{8,}|char\s*\(\s*\d+(\s*,\s*\d+)+\s*\)|concat\s*\()`)},

		// XSS patterns
		{Name: "xss_script_tag", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)<\s*script[^>]*>`)},
		{Name: "xss_event_handler", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)\bon(error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown|mouseout|dblclick|contextmenu|drag|drop)\s*=`)},
		{Name: "xss_javascript_uri", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(javascript|vbscript|data)\s*:`)},
		{Name: "xss_img_tag", Category: "xss", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile(`(?i)<\s*(img|iframe|embed|object|svg|math|video|audio|source)\b[^>]*(src|href|data|action)\s*=`)},
		{Name: "xss_style_expression", Category: "xss", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile(`(?i)(expression\s*\(|url\s*\(\s*(javascript|data):)`)},
		{Name: "xss_dom_manipulation", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(document\.(cookie|write|location|domain)|window\.(location|open)|\.innerHTML\s*=|eval\s*\()`)},

		// Command Injection patterns
		{Name: "cmdi_pipe", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(\||\|\||&&|;|` + "`" + `)\s*(cat|ls|dir|whoami|id|uname|pwd|wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl|ruby|php)\b`)},
		{Name: "cmdi_subshell", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`\$\((cat|ls|whoami|id|uname|pwd|wget|curl|nc|bash|sh)\b`)},
		{Name: "cmdi_backtick", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("`(cat|ls|whoami|id|uname|pwd|wget|curl|nc|bash|sh)\\b")},
		{Name: "cmdi_redirect", Category: "cmdi", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(>\s*/etc/|>\s*/tmp/|<\s*/etc/passwd|/dev/(tcp|udp)/)`)},
		{Name: "cmdi_reverse_shell", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(bash\s+-i\s+>&|nc\s+-[elp]|ncat\s+-|python\s+-c\s+.*socket|perl\s+-e\s+.*socket|ruby\s+-rsocket|php\s+-r\s+.*fsockopen)`)},
		// Management interface RCE — CVE-2025-67840 (WatchGuard XMLRPC) & CVE-2025-63911 (Cohesity API)
		{Name: "cmdi_mgmt_xmlrpc", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)<member><name>(?:os_system|shell_exec|exec)</name><value><string>.*?(?:curl|wget|python|sh|bash).*?</string>`)},
		{Name: "cmdi_mgmt_api_json", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)"(?:command|cmd)":\s*".*?(?:\|\||;|&&)\s*(?:id|whoami|cat|ls|env)"`)},

		// Node.js / server-side JS command injection — CVE-2026-2544 (LuLu UI child_process.exec)
		{Name: "cmdi_nodejs_exec", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(child_process|require\s*\(\s*['"]child_process['"]\s*\))\s*\.\s*(exec|execSync|spawn|spawnSync|execFile|fork)\s*\(`)},
		{Name: "cmdi_nodejs_eval", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(eval|Function|vm\.runInNewContext|vm\.runInThisContext|vm\.createScript)\s*\(`)},
		{Name: "cmdi_nodejs_require", Category: "cmdi", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)require\s*\(\s*['"](fs|net|http|child_process|os|cluster|dgram|dns|tls|crypto)['"]\s*\)`)},

		// CRLF metric injection: a user-controlled value starts a second StatsD-style
		// metric line. Match both literal and percent-encoded line breaks because the
		// analyzer deliberately scans the original input as well as its normalized form.
		{Name: "crlf_metric_injection", Category: "metric", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(?:%0d|%0a|\r|\n)+(?:[a-z0-9_.-]{1,128}):[-+]?[0-9]+(?:\.[0-9]+)?\|(?:c|g|ms|h|s|d)(?:\|[#@][^\r\n&\s]{1,128})?`)},

		// SSRF patterns
		{Name: "ssrf_internal_ip", Category: "ssrf", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(https?://)?(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0|localhost|0x7f|2130706433)`)},
		{Name: "ssrf_cloud_metadata", Category: "ssrf", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`)},
		{Name: "ssrf_file_scheme", Category: "ssrf", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(file|gopher|dict|ftp|ldap|tftp)://`)},
		{Name: "ssrf_dns_rebind", Category: "ssrf", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\.burpcollaborator\.net|\.oastify\.com|\.interact\.sh|\.requestbin\.|\.ngrok\.)`)},

		// LDAP Injection patterns
		{Name: "ldapi_wildcard", Category: "ldapi", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\*\)\(&|\)\(\||\)\(!\(|%2a%29%28)`)},
		{Name: "ldapi_filter", Category: "ldapi", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\(\||\(&|\(!\s*\().*?(uid|cn|sn|mail|objectclass)\s*=`)},

		// Template Injection patterns
		{Name: "template_jinja", Category: "template", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`\{\{.*?(__|class|mro|subclasses|builtins|import|popen|system|eval|exec|getattr).*?\}\}`)},
		{Name: "template_expression", Category: "template", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(\$\{.*?(Runtime|ProcessBuilder|exec|getClass).*?\}|#\{.*?(T\(|new\s+java).*?\})`)},
		{Name: "template_freemarker", Category: "template", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(<#assign|<@|\$\{.*?\.getClass\(\))`)},
		{Name: "template_twig", Category: "template", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`\{\{.*?(system|passthru|exec|popen|file_get_contents).*?\}\}`)},

		// NoSQL Injection patterns
		{Name: "nosql_operator", Category: "nosql", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\$gt|\$lt|\$gte|\$lte|\$ne|\$nin|\$in|\$regex|\$where|\$exists|\$or|\$and|\$not|\$nor)\b`)},
		{Name: "nosql_js_exec", Category: "nosql", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(\$where\s*:\s*['"]?function|this\.\w+\s*==|db\.\w+\.(find|remove|update|drop|insert))`)},
		{Name: "nosql_json_inject", Category: "nosql", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)\{\s*['"]\$\w+['"]\s*:`)},

		// Path Traversal patterns
		{Name: "path_traversal", Category: "path", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\.\.[\\/]|%2e%2e[\\/]|%252e%252e[\\/]|\.\.%2f|%2e%2e%2f){2,}`)},
		// Unicode/NFKC normalization evasion — CVE-2026-25673 (Django on Windows)
		// Detects fullwidth dot/slash lookalikes that normalize to ../ after security filters
		{Name: "path_unicode_nfkc", Category: "path", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(%ef%bc%8e%ef%bc%8e|%ef%bc%8f|%uFF0E%uFF0E|%uFF0F|\x{FF0E}\x{FF0E}[\\/\x{FF0F}]|\x{FF0E}\x{FF0E}\x{FF0F}|%ef%bc%8e\.|\.\x{FF0E}[\\/])`)},
		{Name: "path_sensitive_files", Category: "path", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(/etc/(passwd|shadow|hosts|crontab)|/proc/self/|/windows/system32/|web\.config|\.env|\.git/config|\.htaccess|wp-config\.php)`)},
		{Name: "path_null_byte", Category: "path", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(%00|\\x00|\\0)`)},

		// Zip Slip / Archive Path Traversal patterns
		// Detects path traversal within archive file names targeting extraction paths
		{Name: "zipslip_archive_traversal", Category: "path", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(\.\.[\\/]){1,}.*(\.jsp|\.php|\.sh|\.exe|\.dll|\.py|\.rb|\.war|\.jar|\.aspx|\.bat|\.ps1|\.cgi)`)},
		{Name: "zipslip_webroot_escape", Category: "path", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)\.\.[\\/].*(WEB-INF|META-INF|wwwroot|htdocs|public_html|www|webapps|inetpub)`)},
		{Name: "zipslip_symlink_abuse", Category: "path", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(symlink|\.lnk).*(\.\.[\\/])`)},

		// File Upload Abuse patterns
		// Detects malicious file names in upload contexts (double extensions, polyglot)
		{Name: "upload_double_extension", Category: "upload", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)\.(jpg|png|gif|bmp|pdf|doc|txt)\.(php|jsp|asp|aspx|exe|sh|py|pl|cgi|bat|ps1|war)`)},
		{Name: "upload_null_byte_ext", Category: "upload", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)\.(jpg|png|gif|pdf)(%00|\\x00)\.(php|jsp|asp|exe|sh)`)},
		{Name: "upload_php_wrapper", Category: "upload", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(php://|phar://|zip://|data://text/plain|expect://)`)},

		// Deserialization RCE patterns — addresses Bosch Rexroth (CVE-2025-60035/60037/60038) and similar XML/binary deserialization attacks
		{Name: "deser_java_gadget", Category: "deser", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(ObjectInputStream|readObject|readUnshared|XMLDecoder|xstream|ysoserial|commons-collections|InvokerTransformer|ChainedTransformer|ConstantTransformer|LazyMap)`)},
		{Name: "deser_dotnet", Category: "deser", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(BinaryFormatter|ObjectStateFormatter|SoapFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling|JavaScriptSerializer)`)},
		{Name: "deser_xml_entity", Category: "deser", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(<!ENTITY\s+|<!DOCTYPE\s+[^>]*\[|SYSTEM\s+["']file://|SYSTEM\s+["']http)`)},
		{Name: "deser_php", Category: "deser", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(O:\d+:"[^"]+"|a:\d+:\{|unserialize\s*\(|__wakeup|__destruct)`)},
		{Name: "deser_python_pickle", Category: "deser", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(pickle\.loads|cPickle\.loads|yaml\.load\s*\(|yaml\.unsafe_load|__reduce__|__reduce_ex__)`)},

		// Blind SQLi patterns — addresses the explicit gap in the capability audit
		{Name: "sqli_blind_boolean", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\bAND\b\s+\d+\s*=\s*\d+|\bAND\b\s+['"][^'"]*['"]\s*=\s*['"]|substr(ing)?\s*\(.*,\s*\d+\s*,\s*\d+\s*\)\s*=)`)},
		{Name: "sqli_blind_time", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(pg_sleep\s*\(\s*\d+|dbms_pipe\.receive_message|RANDOMBLOB\s*\(\s*\d{6,}|LIKE\s*'ABCDEFG)`)},
		{Name: "sqli_blind_error", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(convert\s*\(\s*int\s*,|cast\s*\(\s*\(.*\)\s+as\s+int\)|cond\s*\(\s*\d+\s*=\s*\d+)`)},

		// Honeypot / canary token detection — detects when attackers use leaked
		// credentials or tokens that are known canary/honeypot markers. This is a
		// zero-cost deception layer: if someone submits a canary AWS key or known
		// test credential, they're probing with stolen/leaked data.
		{Name: "canary_aws_key", Category: "canary", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{Name: "canary_github_token", Category: "canary", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`)},
		{Name: "canary_slack_token", Category: "canary", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`)},
		{Name: "canary_private_key", Category: "canary", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
		{Name: "canary_jwt_token", Category: "canary", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
		{Name: "canary_gcp_service_account", Category: "canary", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`"type"\s*:\s*"service_account"`)},
	}

	return patterns
}

package supplychain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "supply_chain"

// Sentinel is the Supply Chain Sentinel module providing SBOM generation,
// package integrity verification, CI/CD hardening checks, and typosquatting detection.
type Sentinel struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	pkgTracker   *PackageTracker
	cicdMonitor  *CICDMonitor
	typosquatDet *TyposquatDetector
	codeScanner  *DangerousDefaultScanner
}

func New() *Sentinel { return &Sentinel{} }

func (s *Sentinel) Name() string { return ModuleName }
func (s *Sentinel) Description() string {
	return "SBOM generation, package integrity verification, CI/CD pipeline hardening, and typosquatting detection"
}
func (s *Sentinel) EventTypes() []string {
	return []string{
		"package_install", "dependency_add", "package_update",
		"build_artifact", "artifact_deploy",
		"cicd_event", "pipeline_run", "pipeline_config_change",
		"sbom_scan",
	}
}

func (s *Sentinel) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.bus = bus
	s.pipeline = pipeline
	s.cfg = cfg
	s.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	s.pkgTracker = NewPackageTracker()
	s.cicdMonitor = NewCICDMonitor()
	s.typosquatDet = NewTyposquatDetector()
	s.codeScanner = NewDangerousDefaultScanner()

	s.logger.Info().Msg("supply chain sentinel started")
	return nil
}

func (s *Sentinel) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Sentinel) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "package_install", "dependency_add", "package_update":
		s.handlePackageEvent(event)
	case "build_artifact", "artifact_deploy":
		s.handleArtifactEvent(event)
	case "cicd_event", "pipeline_run", "pipeline_config_change":
		s.handleCICDEvent(event)
	case "sbom_scan":
		s.handleSBOMEvent(event)
	}
	return nil
}

func (s *Sentinel) handlePackageEvent(event *core.SecurityEvent) {
	pkgName := getStringDetail(event, "package_name")
	pkgVersion := getStringDetail(event, "version")
	registry := getStringDetail(event, "registry")
	hash := getStringDetail(event, "hash")
	expectedHash := getStringDetail(event, "expected_hash")

	if pkgName == "" {
		return
	}

	// Typosquatting detection
	if suspect := s.typosquatDet.Check(pkgName, registry); suspect != "" {
		s.raiseAlert(event, core.SeverityHigh,
			"Typosquatting Suspected",
			fmt.Sprintf("Package %q in %s looks like a typosquat of popular package %q. Verify before installing.",
				pkgName, registry, suspect),
			"typosquat")
	}

	// Package integrity check
	if hash != "" && expectedHash != "" && hash != expectedHash {
		s.raiseAlert(event, core.SeverityCritical,
			"Package Integrity Violation",
			fmt.Sprintf("Package %s@%s hash mismatch. Expected: %s, Got: %s. Possible supply chain compromise.",
				pkgName, pkgVersion, truncate(expectedHash, 16), truncate(hash, 16)),
			"integrity_violation")
	}

	// Dependency confusion: private package name appearing in public registry
	if getStringDetail(event, "scope") == "private" && registry == "public" {
		s.raiseAlert(event, core.SeverityCritical,
			"Dependency Confusion Attack",
			fmt.Sprintf("Private package %q resolved from public registry %s. This is a dependency confusion attack vector.",
				pkgName, registry),
			"dependency_confusion")
	}

	// Track the package
	s.pkgTracker.Record(pkgName, pkgVersion, registry, hash)

	// Check for known malicious packages
	if s.pkgTracker.IsKnownMalicious(pkgName) {
		s.raiseAlert(event, core.SeverityCritical,
			"Known Malicious Package",
			fmt.Sprintf("Package %s@%s is flagged as malicious. Remove immediately.", pkgName, pkgVersion),
			"malicious_package")
	}

	packageContext := strings.Join([]string{
		getStringDetail(event, "install_script"),
		getStringDetail(event, "preinstall_script"),
		getStringDetail(event, "postinstall_script"),
		getStringDetail(event, "package_json"),
		getStringDetail(event, "build_log"),
		event.Summary,
	}, "\n")
	if result := s.cicdMonitor.AnalyzeContent(packageContext); result.MaliciousInstallHook {
		s.raiseAlert(event, core.SeverityCritical,
			"Malicious Install Hook Detected",
			fmt.Sprintf("Package %s@%s contains a suspicious preinstall/postinstall script or build log pattern that can fetch and execute remote payloads.",
				pkgName, pkgVersion),
			"malicious_build_artifact")
	}
}

func (s *Sentinel) handleArtifactEvent(event *core.SecurityEvent) {
	artifactName := getStringDetail(event, "artifact_name")
	signature := getStringDetail(event, "signature")
	provenance := getStringDetail(event, "provenance")

	if artifactName == "" {
		return
	}

	// Check for unsigned artifacts
	if signature == "" {
		s.raiseAlert(event, core.SeverityHigh,
			"Unsigned Build Artifact",
			fmt.Sprintf("Artifact %s has no signature. Build artifacts should be signed for integrity verification.", artifactName),
			"unsigned_artifact")
	}

	// Check for missing provenance
	if provenance == "" {
		s.raiseAlert(event, core.SeverityMedium,
			"Missing Artifact Provenance",
			fmt.Sprintf("Artifact %s has no provenance attestation. Cannot verify build origin.", artifactName),
			"missing_provenance")
	}

	for _, finding := range s.codeScanner.Scan(strings.Join([]string{
		getStringDetail(event, "artifact_preview"),
		getStringDetail(event, "artifact_content"),
		getStringDetail(event, "code_snippet"),
		getStringDetail(event, "build_log"),
		event.Summary,
	}, "\n")) {
		s.raiseAlert(event, finding.Severity, finding.Title,
			fmt.Sprintf("Artifact %s contains insecure implementation guidance: %s", artifactName, finding.Description),
			finding.AlertType)
	}
}

func (s *Sentinel) handleCICDEvent(event *core.SecurityEvent) {
	action := getStringDetail(event, "action")
	pipelineName := getStringDetail(event, "pipeline_name")
	user := getStringDetail(event, "user")
	pipelineContext := strings.Join([]string{
		action,
		getStringDetail(event, "pipeline_config"),
		getStringDetail(event, "script"),
		getStringDetail(event, "diff"),
		getStringDetail(event, "build_log"),
		event.Summary,
	}, "\n")

	if action == "" && strings.TrimSpace(pipelineContext) == "" {
		return
	}

	result := s.cicdMonitor.Analyze(action, pipelineName, user, event.SourceIP)
	contentResult := s.cicdMonitor.AnalyzeContent(pipelineContext)

	if result.UnauthorizedChange {
		s.raiseAlert(event, core.SeverityCritical,
			"Unauthorized CI/CD Pipeline Change",
			fmt.Sprintf("User %s modified pipeline %q from IP %s. This change was not authorized.",
				user, pipelineName, event.SourceIP),
			"unauthorized_cicd_change")
	}

	if contentResult.MaliciousInstallHook {
		s.raiseAlert(event, core.SeverityCritical,
			"Malicious CI/CD Install Hook Detected",
			fmt.Sprintf("Pipeline %q contains an obfuscated preinstall/postinstall execution chain capable of downloading and running remote code.",
				pipelineName),
			"malicious_build_artifact")
	} else if result.SuspiciousStep || contentResult.SuspiciousStep {
		s.raiseAlert(event, core.SeverityHigh,
			"Suspicious CI/CD Step Detected",
			fmt.Sprintf("Pipeline %q contains suspicious step: %s", pipelineName, action),
			"suspicious_cicd_step")
	}

	if result.SecretExposure || contentResult.SecretExposure {
		s.raiseAlert(event, core.SeverityCritical,
			"Secret Exposure in CI/CD",
			fmt.Sprintf("Pipeline %q may be exposing secrets in logs or artifacts.", pipelineName),
			"cicd_secret_exposure")
	}

	for _, finding := range s.codeScanner.Scan(pipelineContext) {
		s.raiseAlert(event, finding.Severity, finding.Title,
			fmt.Sprintf("Pipeline %q contains insecure code or config defaults: %s", pipelineName, finding.Description),
			finding.AlertType)
	}
}

func (s *Sentinel) handleSBOMEvent(event *core.SecurityEvent) {
	vulnCount := getIntDetail(event, "vulnerability_count")
	criticalCount := getIntDetail(event, "critical_count")
	highCount := getIntDetail(event, "high_count")

	if criticalCount > 0 {
		s.raiseAlert(event, core.SeverityCritical,
			"Critical Vulnerabilities in Dependencies",
			fmt.Sprintf("SBOM scan found %d critical and %d high vulnerabilities across %d total findings.",
				criticalCount, highCount, vulnCount),
			"sbom_critical_vulns")
	} else if highCount > 0 {
		s.raiseAlert(event, core.SeverityHigh,
			"High Vulnerabilities in Dependencies",
			fmt.Sprintf("SBOM scan found %d high vulnerabilities across %d total findings.", highCount, vulnCount),
			"sbom_high_vulns")
	}
}

func (s *Sentinel) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if s.bus != nil {
		_ = s.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = getSupplyChainMitigations(alertType)
	if s.pipeline != nil {
		s.pipeline.Process(alert)
	}
}

// PackageTracker tracks installed packages and known malicious ones.
type PackageTracker struct {
	mu        sync.RWMutex
	packages  map[string]*PackageRecord
	malicious map[string]bool
}

type DangerousDefaultScanner struct {
	patterns []DangerousDefaultPattern
}

type DangerousDefaultPattern struct {
	Title       string
	Description string
	Severity    core.Severity
	AlertType   string
	Regex       *regexp.Regexp
}

func NewDangerousDefaultScanner() *DangerousDefaultScanner {
	return &DangerousDefaultScanner{
		patterns: []DangerousDefaultPattern{
			{
				Title:       "TLS Verification Disabled in Generated Code",
				Description: "code disables certificate validation or hostname verification, which turns HTTPS into plaintext-with-extra-steps",
				Severity:    core.SeverityCritical,
				AlertType:   "dangerous_code_default",
				Regex:       regexp.MustCompile(`(?i)(insecureskipverify\s*:\s*true|verify\s*=\s*false|rejectunauthorized\s*:\s*false|curl\s+-k\b|ssl\._create_unverified_context)`),
			},
			{
				Title:       "Hardcoded Default Credential in Artifact",
				Description: "artifact includes a static password, token, or bootstrap secret that AI assistants frequently emit as a placeholder and teams forget to rotate",
				Severity:    core.SeverityHigh,
				AlertType:   "dangerous_code_default",
				Regex:       regexp.MustCompile(`(?i)((password|passwd|token|api[_-]?key|secret)\s*[:=]\s*["'](?:admin|changeme|password|secret|test123|default|root)["'])`),
			},
			{
				Title:       "Weak Cryptographic Default in Artifact",
				Description: "artifact relies on legacy or collision-prone cryptography that should never be used as a default implementation",
				Severity:    core.SeverityHigh,
				AlertType:   "dangerous_code_default",
				Regex:       regexp.MustCompile(`(?i)(hashlib\.md5|md5\s*\(|sha1\s*\(|createHash\(["']md5["']\)|createHash\(["']sha1["']\)|cipher\.getinstance\(["'](?:des|rc4)["'])`),
			},
			{
				Title:       "Legacy TLS Version Default in Artifact",
				Description: "artifact pins TLSv1.0/TLSv1.1 or similarly deprecated protocol defaults that modern deployments should reject",
				Severity:    core.SeverityHigh,
				AlertType:   "dangerous_code_default",
				Regex:       regexp.MustCompile(`(?i)(tlsv1[\._](?:0|1)|sslcontext\.getinstance\(["']tlsv1\.[01]["']\)|securityprotocoltype\.(?:tls|tls11)\b)`),
			},
			{
				Title:       "Zeroed Key Material Placeholder",
				Description: "artifact includes all-zero or trivially initialized key bytes that often originate from generated placeholder crypto examples",
				Severity:    core.SeverityHigh,
				AlertType:   "dangerous_code_default",
				Regex:       regexp.MustCompile(`(?i)(new\s+byte\s*\[\s*\]\s*\{\s*0\s*(?:,\s*0\s*){7,}\}|bytes?\(\s*\[\s*0\s*(?:,\s*0\s*){7,}\])`),
			},
			{
				Title:       "Permissive CORS With Credentials",
				Description: "artifact combines wildcard origins with credentialed requests, a common insecure default in generated backend examples",
				Severity:    core.SeverityHigh,
				AlertType:   "dangerous_code_default",
				Regex:       regexp.MustCompile(`(?is)(access-control-allow-origin\s*[:=]\s*["']\*["'].*access-control-allow-credentials\s*[:=]\s*["']?true|allowcredentials\s*[:=]\s*true.*alloworigin[s]?\s*[:=]\s*["']\*["'])`),
			},
			{
				Title:       "Live Token Embedded in Artifact",
				Description: "artifact contains a real-looking provider token, suggesting generated sample code leaked production-style credentials directly into source or build output",
				Severity:    core.SeverityCritical,
				AlertType:   "dangerous_code_default",
				Regex:       regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,}|xox[baprs]-[0-9A-Za-z-]{20,})`),
			},
		},
	}
}

func (s *DangerousDefaultScanner) Scan(content string) []DangerousDefaultPattern {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	var findings []DangerousDefaultPattern
	for _, pattern := range s.patterns {
		if pattern.Regex.MatchString(content) {
			findings = append(findings, pattern)
		}
	}
	return findings
}

type PackageRecord struct {
	Name      string
	Version   string
	Registry  string
	Hash      string
	FirstSeen time.Time
}

func NewPackageTracker() *PackageTracker {
	pt := &PackageTracker{
		packages:  make(map[string]*PackageRecord),
		malicious: make(map[string]bool),
	}
	// Seed with known malicious package patterns
	knownMalicious := []string{
		"event-stream-malicious", "flatmap-stream",
		"ua-parser-js-malicious", "coa-malicious",
		"colors-malicious", "faker-malicious",
		"peacenotwar", "node-ipc-malicious",
	}
	for _, pkg := range knownMalicious {
		pt.malicious[pkg] = true
	}
	return pt
}

func (pt *PackageTracker) Record(name, version, registry, hash string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	key := registry + ":" + name
	pt.packages[key] = &PackageRecord{
		Name: name, Version: version, Registry: registry,
		Hash: hash, FirstSeen: time.Now(),
	}
}

func (pt *PackageTracker) IsKnownMalicious(name string) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return pt.malicious[strings.ToLower(name)]
}

// CICDMonitor analyzes CI/CD pipeline events for security issues.
type CICDMonitor struct {
	mu              sync.RWMutex
	authorizedUsers map[string]bool
	installHookRX   *regexp.Regexp
	suspiciousSteps *regexp.Regexp
	secretPatterns  *regexp.Regexp
}

type CICDResult struct {
	UnauthorizedChange   bool
	MaliciousInstallHook bool
	SuspiciousStep       bool
	SecretExposure       bool
}

func NewCICDMonitor() *CICDMonitor {
	return &CICDMonitor{
		authorizedUsers: make(map[string]bool),
		installHookRX:   regexp.MustCompile(`(?i)(preinstall|postinstall).*?(curl|wget|base64|eval).*?(\|\s*bash|\|\s*sh|\.sh)`),
		suspiciousSteps: regexp.MustCompile(`(?i)(curl\s+.*\|\s*sh|wget\s+.*\|\s*bash|eval\s*\(|base64\s+-d|nc\s+-[elp]|reverse.?shell|crypto.?min|curl\s+https?://|wget\s+https?://)`),
		secretPatterns:  regexp.MustCompile(`(?i)(echo\s+\$\{?[A-Z_]*SECRET|echo\s+\$\{?[A-Z_]*TOKEN|echo\s+\$\{?[A-Z_]*PASSWORD|echo\s+\$\{?[A-Z_]*KEY|printenv|env\s*$|set\s*$)`),
	}
}

func (cm *CICDMonitor) Analyze(action, pipeline, user, ip string) CICDResult {
	result := cm.analyzeContent(action)

	cm.mu.RLock()
	if len(cm.authorizedUsers) > 0 && !cm.authorizedUsers[user] {
		result.UnauthorizedChange = true
	}
	cm.mu.RUnlock()

	return result
}

func (cm *CICDMonitor) AnalyzeContent(content string) CICDResult {
	return cm.analyzeContent(content)
}

func (cm *CICDMonitor) analyzeContent(content string) CICDResult {
	result := CICDResult{}
	if cm.suspiciousSteps.MatchString(content) {
		result.SuspiciousStep = true
	}
	if cm.installHookRX.MatchString(content) {
		result.MaliciousInstallHook = true
	}
	if cm.secretPatterns.MatchString(content) {
		result.SecretExposure = true
	}
	return result
}

// TyposquatDetector detects potential typosquatting attacks on package names.
type TyposquatDetector struct {
	popularPackages map[string][]string // registry -> list of popular package names
}

func NewTyposquatDetector() *TyposquatDetector {
	return &TyposquatDetector{
		popularPackages: map[string][]string{
			"npm": {
				"lodash", "express", "react", "axios", "moment",
				"webpack", "typescript", "next", "vue", "angular",
				"jquery", "chalk", "commander", "debug", "request",
				"dotenv", "cors", "uuid", "jsonwebtoken", "bcrypt",
				"mongoose", "sequelize", "prisma", "socket.io",
				"react-dom", "tailwindcss", "vite", "eslint", "prettier",
				"jest", "zod", "rxjs", "dayjs", "date-fns",
				"nanoid", "node-fetch", "undici", "esbuild", "tslib",
				"yaml", "cross-env", "rimraf", "postcss", "autoprefixer",
				"@types/node", "@types/react", "@types/react-dom", "pnpm", "npm",
				"react-router-dom", "redux", "zustand", "tanstack-query", "tanstack-table",
				"tanstack-router", "tanstack-virtual", "tanstack-form", "tanstack-ranger",
				"framer-motion", "styled-components", "emotion", "mui", "mantine",
				"shadcn-ui", "radix-ui", "headlessui", "heroicons", "lucide-react",
				"react-query", "swr", "apollo-client", "urql", "graphql",
				"graphql-request", "dataloader", "type-graphql", "nexus", "pothos",
				"trpc", "zodios", "ts-rest", "openapi-typescript", "swagger-ui",
				"express-validator", "joi", "yup", "superstruct", "runtypes",
				"io-ts", "class-validator", "class-transformer", "reflect-metadata", "tsyringe",
				"inversify", "awilix", "bottlejs", "di-lib", "type-di",
				"nodemon", "ts-node", "tsx", "vite-node", "esbuild-register",
				"babel-loader", "ts-loader", "swc-loader", "thread-loader", "cache-loader",
				"html-webpack-plugin", "mini-css-extract-plugin", "terser-webpack-plugin", "css-minimizer-webpack-plugin", "image-minimizer-webpack-plugin",
				"copy-webpack-plugin", "clean-webpack-plugin", "webpack-bundle-analyzer", "speed-measure-webpack-plugin", "webpackbar",
				"rollup", "rollup-plugin-dts", "rollup-plugin-esbuild", "rollup-plugin-typescript2", "rollup-plugin-postcss",
				"parcel", "turbo", "nx", "lerna", "changesets",
				"husky", "lint-staged", "commitlint", "semantic-release", "standard-version",
				"release-it", "np", "gh-pages", "netlify-cli", "vercel",
				"aws-sdk", "azure-sdk", "google-cloud", "firebase", "supabase",
				"prisma-client", "drizzle-orm", "kysely", "typeorm", "sequelize-typescript",
				"knex", "objection", "bookshelf", "waterline", "shelf",
				"mongodb", "mongoose", "monk", "mongojs", "connect-mongo",
				"ioredis", "redis", "bull", "bullmq", "bee-queue",
				"agenda", "node-cron", "cron", "node-schedule", "bree",
				"puppeteer", "playwright", "cypress", "selenium-webdriver", "webdriverio",
				"jest", "vitest", "mocha", "chai", "sinon",
				"ava", "tap", "tape", "qunit", "jasmine",
				"cucumber", "gherkin", "codeceptjs", "nightwatch", "testcafe",
				"nyc", "c8", "istanbul", "codecov", "coveralls",
				"husky", "lint-staged", "eslint", "prettier", "stylelint",
				"commitizen", "cz-conventional-changelog", "standard-version", "semantic-release", "release-it",
				"np", "gh-pages", "netlify-cli", "vercel", "serverless",
				"terraform-cdk", "cdktf", "pulumi", "aws-cdk", "cdk8s",
				"cdktf-cli", "serverless-offline", "serverless-webpack", "serverless-esbuild", "serverless-prune-plugin",
				"winston", "pino", "bunyan", "log4js", "consola",
				"debug", "ndb", "iron-node", "node-inspector", "clinic",
				"0x", "clinic-doctor", "clinic-flame", "clinic-bubbleprof", "autocannon",
				"artillery", "k6", "loadtest", "ab", "siege",
				"nodemailer", "sendgrid", "mailgun-js", "aws-ses", "postmark",
				"twilio", "stripe", "braintree", "paypal-rest-sdk", "square",
				"plaid", " Dwolla", "adyen", "checkout-sdk", "razorpay",
				"sharp", "imagemagick", "gm", "jimp", "canvas",
				"fabric", "konva", "pixi.js", "three", "babylonjs",
				"d3", "chart.js", "echarts", "recharts", "victory",
				"plotly.js", "apexcharts", "highcharts", "fusioncharts", "amcharts",
				"pdfkit", "puppeteer-pdf", "html-pdf", "wkhtmltopdf", "jsPDF",
				"xlsx", "csv-parse", "csv-stringify", "fast-csv", "papaparse",
				"multer", "formidable", "busboy", "express-fileupload", "connect-busboy",
				"sharp", "ffmpeg-static", "fluent-ffmpeg", "wavefile", "tone",
			},
			"pypi": {
				"requests", "numpy", "pandas", "flask", "django",
				"boto3", "tensorflow", "torch", "scikit-learn", "pillow",
				"matplotlib", "sqlalchemy", "celery", "fastapi", "pydantic",
				"cryptography", "paramiko", "beautifulsoup4", "selenium",
				"urllib3", "jinja2", "pyyaml", "pytest", "setuptools",
				"wheel", "pip", "click", "aiohttp", "starlette",
				"uvicorn", "redis", "psycopg2", "psycopg", "mysqlclient",
				"transformers", "openai", "anthropic", "httpx", "orjson",
				"django-rest-framework", "flask-restful", "fastapi-users", "tortoise-orm", "ormar",
				"peewee", "pony", "sqlmodel", "encode-databases", "asyncpg",
				"aiomysql", "aiosqlite", "trio", "anyio", "sniffio",
				"gevent", "eventlet", "greenlet", "twisted", "tornado",
				"sanic", "quart", "falcon", "hug", "apistar",
				"bottle", "cherrypy", "web2py", "pyramid", "zope",
				"plone", "django-cms", "wagtail", "mezzanine", "feincms",
				"graphene", "ariadne", "strawberry-graphql", "tartiflette", "graphql-core",
				"pydantic-settings", "python-dotenv", "dynaconf", "confuse", "configobj",
				"hydra-core", "omegaconf", "dacite", "marshmallow", "cerberus",
				"voluptuous", "schema", "traitlets", "attrs", "dataclasses",
				"pydantic-extra-types", "pydantic-ai", "langchain", "llama-index", "haystack",
				"chromadb", "weaviate-client", "qdrant-client", "pinecone-client", "milvus",
				"faiss-cpu", "annoy", "hnswlib", "scann", "nmslib",
				"sentence-transformers", "spacy", "nltk", "textblob", "gensim",
				"stanza", "transformers", "tokenizers", "datasets", "accelerate",
				"diffusers", "peft", "trl", "bitsandbytes", "auto-gptq",
				"vllm", "text-generation-inference", "mlflow", "wandb", "tensorboard",
				"optuna", "ray", "dask", "modin", "polars",
				"pyarrow", "duckdb", "sqlite3", "sqlalchemy", "alembic",
				"mypy", "black", "isort", "flake8", "pylint",
				"bandit", "safety", "pip-audit", "semgrep", "codeql",
				"pre-commit", "tox", "nox", "invoke", "fabric",
				"ansible", "salt", "puppet", "chef", "terraform-python",
				"pulumi-python", "cdk8s-python", "aws-cdk-lib", "cdktf-python", "serverless-python",
				"boto3", "botocore", "awscli", "azure-cli", "google-cloud-sdk",
				"kubernetes", "helm", "openshift", "docker", "podman",
				"fabric", "invoke", "paramiko", "pexpect", "ptyprocess",
				"scrapy", "splash", "playwright-python", "selenium-wire", "requests-html",
				"httpx", "aiohttp", "trio", "anyio", "asks",
				"urllib3", "chardet", "charset-normalizer", "idna", "certifi",
				"cryptography", "pyopenssl", "pynacl", "bcrypt", "argon2-cffi",
				"passlib", "hashlib", "hmac", "secrets", "uuid",
				"jsonschema", "cerberus", "voluptuous", "schema", "trafaret",
				"pydantic", "marshmallow", "dataclasses-json", "cattrs", "apispec",
				"flasgger", "drf-yasg", "fastapi-versioning", "starlette-context", "asgiref",
				"uvloop", "watchgod", "watchfiles", "python-multipart", "python-jose",
				"passlib", "python-jwt", "pyjwt", "authlib", "oauthlib",
				"requests-oauthlib", "flask-oauthlib", "django-oauth-toolkit", "fastapi-oauth2", "social-auth-core",
				"pillow", "opencv-python", "imageio", "scikit-image", "mahotas",
				"pytesseract", "easyocr", "keras-ocr", "paddleocr", "mmocr",
				"moviepy", "imageio-ffmpeg", "pydub", "librosa", "soundfile",
				"audioread", "resampy", "madmom", "essentia", "aubio",
				"pandas", "numpy", "scipy", "statsmodels", "sympy",
				"networkx", "igraph", "graph-tool", "pygraphistry", "snap",
				"plotly", "bokeh", "altair", "seaborn", "holoviews",
				"panel", "datashader", "geoviews", "cartopy", "geopandas",
				"shapely", "fiona", "rasterio", "xarray", "netcdf4",
				"h5py", "tables", "zarr", "dask", "modin",
				"ray", "polars", "pyarrow", "duckdb", "sqlalchemy",
			},
			"public": {
				"lodash", "express", "react", "requests", "numpy",
				"pandas", "flask", "django", "axios", "webpack",
				"fastapi", "typescript", "tailwindcss", "urllib3", "pydantic",
				"next", "vue", "angular", "jquery", "chalk",
				"commander", "debug", "dotenv", "cors", "uuid",
				"jsonwebtoken", "bcrypt", "mongoose", "sequelize", "prisma",
				"socket.io", "react-dom", "vite", "eslint", "prettier",
				"jest", "zod", "rxjs", "dayjs", "date-fns",
				"matplotlib", "sqlalchemy", "celery", "cryptography", "paramiko",
				"beautifulsoup4", "urllib3", "jinja2", "pyyaml", "pytest",
				"setuptools", "wheel", "pip", "click", "aiohttp",
				"starlette", "uvicorn", "redis", "psycopg2", "psycopg",
				"mysqlclient", "transformers", "openai", "anthropic", "httpx",
				"orjson", "langchain", "llama-index", "chromadb", "polars",
			},
		},
	}
}

func (td *TyposquatDetector) Check(pkgName, registry string) string {
	popular, ok := td.popularPackages[strings.ToLower(registry)]
	if !ok {
		popular = td.popularPackages["public"]
	}

	nameLower := strings.ToLower(pkgName)

	// First pass: exact match — if the package is in our baseline, it's legitimate
	for _, pkg := range popular {
		if nameLower == pkg {
			return "" // exact match, not a typosquat
		}
	}

	// Second pass: typosquat heuristics
	for _, pkg := range popular {
		dist := levenshtein(nameLower, pkg)
		if dist <= 2 && dist > 0 {
			return pkg
		}
		// Check for common typosquat patterns
		if strings.ReplaceAll(nameLower, "-", "") == strings.ReplaceAll(pkg, "-", "") && nameLower != pkg {
			return pkg
		}
		if strings.ReplaceAll(nameLower, "_", "-") == pkg || strings.ReplaceAll(nameLower, "-", "_") == pkg {
			return pkg
		}
	}
	return ""
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	matrix := make([][]int, la+1)
	for i := range matrix {
		matrix[i] = make([]int, lb+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				min(matrix[i][j-1]+1, matrix[i-1][j-1]+cost),
			)
		}
	}
	return matrix[la][lb]
}

// HashBytes returns the SHA-256 hex digest of data.
func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	switch values := event.Details[key].(type) {
	case []string:
		return strings.Join(values, "\n")
	case []interface{}:
		var lines []string
		for _, value := range values {
			if text, ok := value.(string); ok {
				lines = append(lines, text)
			}
		}
		return strings.Join(lines, "\n")
	}
	return ""
}

func getIntDetail(event *core.SecurityEvent, key string) int {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// getSupplyChainMitigations returns context-specific mitigations based on alert type.
func getSupplyChainMitigations(alertType string) []string {
	switch alertType {
	case "typosquat":
		return []string{
			"Verify the package name against the official registry listing",
			"Check package download counts, author, and publication date",
			"Use lockfiles and hash pinning to prevent substitution",
			"Implement package name validation in CI/CD pipelines",
		}
	case "package_integrity_violation":
		return []string{
			"Do not install the package — hash mismatch indicates tampering",
			"Verify the package hash against the official registry",
			"Check if the registry has been compromised",
			"Use signed packages and verify signatures before installation",
		}
	case "dependency_confusion":
		return []string{
			"Configure package managers to prioritize private registries",
			"Use scoped packages or namespaces to prevent confusion",
			"Register placeholder packages on public registries for private package names",
			"Implement registry allowlisting in your package manager configuration",
		}
	case "known_malicious_package", "malicious_package":
		return []string{
			"Remove the package immediately from all environments",
			"Audit systems where the package was installed for compromise indicators",
			"Rotate any credentials that may have been exposed",
			"Report the package to the registry maintainers",
		}
	case "malicious_build_artifact":
		return []string{
			"Block the build output and quarantine the artifact until the install hook is reviewed",
			"Remove preinstall/postinstall hooks that fetch or execute remote code",
			"Pin dependency versions and hashes so install-time drift is visible in CI/CD",
			"Treat obfuscated base64, eval, curl|sh, and wget|bash chains as high-risk by default",
		}
	case "unsigned_artifact":
		return []string{
			"Implement artifact signing in your build pipeline (e.g., Sigstore, cosign)",
			"Require signature verification before deployment",
			"Use SLSA framework for build provenance attestation",
		}
	case "missing_provenance":
		return []string{
			"Implement build provenance attestation (SLSA Level 2+)",
			"Use reproducible builds to enable independent verification",
			"Require provenance for all artifacts before deployment",
		}
	case "unauthorized_cicd_change":
		return []string{
			"Require code review and approval for all CI/CD pipeline changes",
			"Implement branch protection rules on pipeline configuration files",
			"Use infrastructure-as-code with version control for pipeline definitions",
			"Monitor and alert on pipeline configuration changes",
		}
	case "suspicious_cicd_step":
		return []string{
			"Review the suspicious pipeline step for malicious intent",
			"Implement allowlists for permitted CI/CD actions and commands",
			"Use hardened, minimal base images for CI/CD runners",
		}
	case "cicd_secret_exposure":
		return []string{
			"Rotate all secrets that may have been exposed",
			"Use secret management tools (Vault, AWS Secrets Manager) instead of env vars",
			"Implement secret scanning in CI/CD logs and artifacts",
			"Mask secrets in CI/CD output and disable debug logging in production",
		}
	case "sbom_critical_vulns", "sbom_high_vulns":
		return []string{
			"Prioritize patching critical and high vulnerabilities",
			"Implement automated dependency updates with security scanning",
			"Use SBOM scanning in CI/CD to block deployments with critical vulns",
			"Monitor vulnerability databases for new disclosures affecting your dependencies",
		}
	default:
		return []string{
			"Verify package integrity using checksums and signatures",
			"Use a private registry mirror with allow-listing",
			"Implement SBOM scanning in your CI/CD pipeline",
		}
	}
}

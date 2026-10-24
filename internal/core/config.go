package core

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config holds the entire 1SEC configuration.
type Config struct {
	Server           ServerConfig            `yaml:"server"`
	Bus              BusConfig               `yaml:"bus"`
	Alerts           AlertConfig             `yaml:"alerts"`
	Syslog           SyslogConfig            `yaml:"syslog"`
	Modules          map[string]ModuleConfig `yaml:"modules"`
	Logging          LoggingConfig           `yaml:"logging"`
	RustEngine       RustEngineConfig        `yaml:"rust_engine"`
	Enforcement      *EnforcementConfig      `yaml:"enforcement,omitempty"`
	Archive          ArchiveConfig           `yaml:"archive"`
	Cloud            CloudConfig             `yaml:"cloud"`
	TokenVault       TokenVaultConfig        `yaml:"token_vault"`
	Escalation       EscalationConfig        `yaml:"escalation"`
	ManagementAccess ManagementAccessConfig  `yaml:"management_access"`
}

// TokenVaultConfig holds settings for Auth0 Token Vault integration.
// Token Vault is a sub-component of AI Containment (Module 11) that enables
// secure OAuth 2.0 token delegation for AI agents via Auth0.
type TokenVaultConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Auth0Domain       string `yaml:"auth0_domain"`
	Auth0ClientID     string `yaml:"auth0_client_id"`
	Auth0ClientSecret string `yaml:"auth0_client_secret"`
}

// CloudConfig holds settings for reporting to the 1SEC cloud dashboard.
type CloudConfig struct {
	Enabled               bool   `yaml:"enabled"`
	APIURL                string `yaml:"api_url"`
	APIKey                string `yaml:"api_key"`
	HeartbeatInterval     int    `yaml:"heartbeat_interval"`      // seconds, <= 0 uses 60
	CommandPollInterval   int    `yaml:"command_poll_interval"`   // seconds, <= 0 uses 15 when explicitly enabled
	RemoteCommandsEnabled bool   `yaml:"remote_commands_enabled"` // opt-in; telemetry never grants remote control
	InstanceID            string `yaml:"instance_id"`             // enrolled device identity; unique per engine
}

// EnforcementConfig holds the automated response / enforcement layer settings.
type EnforcementConfig struct {
	Enabled         bool                          `yaml:"enabled"`
	DryRun          bool                          `yaml:"dry_run"`
	Preset          string                        `yaml:"preset,omitempty"` // "lax", "safe", "balanced", "strict", "vps-agent"
	GlobalAllowList []string                      `yaml:"global_allow_list,omitempty"`
	Policies        map[string]ResponsePolicyYAML `yaml:"policies,omitempty"`
	ApprovalGate    ApprovalGateConfig            `yaml:"approval_gate"`
	mu              sync.RWMutex                  `yaml:"-"` // protects DryRun from concurrent access
}

// GetDryRun returns the current dry-run state (thread-safe).
func (ec *EnforcementConfig) GetDryRun() bool {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.DryRun
}

// SetDryRun sets the dry-run state (thread-safe).
func (ec *EnforcementConfig) SetDryRun(v bool) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.DryRun = v
}

// ResponsePolicyYAML is the YAML-friendly representation of a response policy.
type ResponsePolicyYAML struct {
	Module           string             `yaml:"-"`
	Enabled          bool               `yaml:"enabled"`
	MinSeverity      string             `yaml:"min_severity"`
	Actions          []ResponseRuleYAML `yaml:"actions"`
	CooldownSeconds  int                `yaml:"cooldown_seconds"`
	DryRun           bool               `yaml:"dry_run"`
	AllowList        []string           `yaml:"allow_list,omitempty"`
	MaxActionsPerMin int                `yaml:"max_actions_per_min"`
}

// ResponseRuleYAML is the YAML-friendly representation of a response rule.
type ResponseRuleYAML struct {
	Action       string            `yaml:"action"`
	MinSeverity  string            `yaml:"min_severity"`
	Params       map[string]string `yaml:"params,omitempty"`
	DryRun       bool              `yaml:"dry_run"`
	SkipApproval bool              `yaml:"skip_approval,omitempty"` // bypass approval gate for this rule
	Description  string            `yaml:"description,omitempty"`
}

// ServerConfig holds API server settings.
type ServerConfig struct {
	Host                     string   `yaml:"host"`
	Port                     int      `yaml:"port"`
	APIKeys                  []string `yaml:"api_keys"`
	ReadOnlyKeys             []string `yaml:"read_only_keys"`
	AllowUnauthenticatedRead bool     `yaml:"allow_unauthenticated_read"`
	CORSOrigins              []string `yaml:"cors_origins"`
	TLSCert                  string   `yaml:"tls_cert"` // path to TLS certificate file
	TLSKey                   string   `yaml:"tls_key"`  // path to TLS private key file
}

// SyslogConfig holds syslog ingestion settings.
type SyslogConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Protocol string `yaml:"protocol"` // "udp", "tcp", or "both"
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
}

// BusConfig holds NATS event bus settings.
type BusConfig struct {
	URL       string `yaml:"url"`
	Embedded  bool   `yaml:"embedded"`
	DataDir   string `yaml:"data_dir"`
	Port      int    `yaml:"port"`
	ClusterID string `yaml:"cluster_id"`
}

// AlertConfig holds alert pipeline settings.
type AlertConfig struct {
	MaxStore      int      `yaml:"max_store"`
	WebhookURLs   []string `yaml:"webhook_urls"`
	EnableConsole bool     `yaml:"enable_console"`
}

// ModuleConfig holds per-module configuration.
type ModuleConfig struct {
	Enabled  bool                   `yaml:"enabled"`
	Settings map[string]interface{} `yaml:"settings"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// RustEngineConfig holds settings for the optional Rust sidecar engine.
type RustEngineConfig struct {
	Enabled              bool              `yaml:"enabled"`
	Binary               string            `yaml:"binary"`
	Workers              int               `yaml:"workers"`
	BufferSize           int               `yaml:"buffer_size"`
	MinScore             float64           `yaml:"min_score"`
	AhoCorasickPrefilter bool              `yaml:"aho_corasick_prefilter"`
	Capture              RustCaptureConfig `yaml:"capture"`
}

// RustCaptureConfig holds packet capture settings for the Rust engine.
type RustCaptureConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Interface   string `yaml:"interface"`
	BPFFilter   string `yaml:"bpf_filter"`
	Promiscuous bool   `yaml:"promiscuous"`
}

// DefaultConfig returns a Config with sane defaults — zero-config works out of the box.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 1780,
		},
		Bus: BusConfig{
			URL:       "nats://127.0.0.1:4222",
			Embedded:  true,
			DataDir:   "./data/nats",
			Port:      4222,
			ClusterID: "1sec-cluster",
		},
		Alerts: AlertConfig{
			MaxStore:      10000,
			EnableConsole: true,
		},
		Syslog: SyslogConfig{
			Enabled:  false,
			Protocol: "udp",
			Host:     "0.0.0.0",
			Port:     1514,
		},
		Modules: map[string]ModuleConfig{
			"network_guardian":   {Enabled: true, Settings: map[string]interface{}{}},
			"api_fortress":       {Enabled: true, Settings: map[string]interface{}{}},
			"iot_shield":         {Enabled: true, Settings: map[string]interface{}{}},
			"injection_shield":   {Enabled: true, Settings: map[string]interface{}{}},
			"supply_chain":       {Enabled: true, Settings: map[string]interface{}{}},
			"ransomware":         {Enabled: true, Settings: map[string]interface{}{}},
			"auth_fortress":      {Enabled: true, Settings: map[string]interface{}{}},
			"deepfake_shield":    {Enabled: true, Settings: map[string]interface{}{}},
			"identity_monitor":   {Enabled: true, Settings: map[string]interface{}{}},
			"llm_firewall":       {Enabled: true, Settings: map[string]interface{}{}},
			"ai_containment":     {Enabled: true, Settings: map[string]interface{}{}},
			"data_poisoning":     {Enabled: true, Settings: map[string]interface{}{}},
			"quantum_crypto":     {Enabled: true, Settings: map[string]interface{}{}},
			"runtime_watcher":    {Enabled: true, Settings: map[string]interface{}{}},
			"cloud_posture":      {Enabled: true, Settings: map[string]interface{}{}},
			"ai_analysis_engine": {Enabled: true, Settings: map[string]interface{}{}},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "console",
		},
		RustEngine: RustEngineConfig{
			Enabled:              false,
			Binary:               "1sec-engine",
			Workers:              0,
			BufferSize:           10000,
			MinScore:             0.1,
			AhoCorasickPrefilter: true,
			Capture: RustCaptureConfig{
				Enabled:     false,
				Interface:   "eth0",
				BPFFilter:   "",
				Promiscuous: true,
			},
		},
		Archive: DefaultArchiveConfig(),
		Cloud: CloudConfig{
			Enabled:           false,
			APIURL:            "https://1-sec.dev/api/v1",
			HeartbeatInterval: 60,
		},
		Escalation: DefaultEscalationConfig(),
	}
}

// ConfigFileMode is used for config writes because config files can contain
// API keys, cloud tokens, webhook credentials, and model provider keys.
const ConfigFileMode os.FileMode = 0600

// LoadConfigOptions controls compatibility behavior for config parsing.
type LoadConfigOptions struct {
	AllowUnknownFields bool
}

// LoadConfig loads configuration from a YAML file, falling back to defaults.
func LoadConfig(path string) (*Config, error) {
	return LoadConfigWithOptions(path, LoadConfigOptions{
		AllowUnknownFields: envBool("ONESEC_ALLOW_UNKNOWN_CONFIG_FIELDS"),
	})
}

// LoadConfigWithOptions loads configuration from a YAML file with explicit
// compatibility options.
func LoadConfigWithOptions(path string, opts LoadConfigOptions) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		data = nil
	}

	// Use strict YAML decoding to reject unknown fields that could indicate
	// injection of unexpected execution tags (CVE-2026-4292 prevention).
	if data == nil {
		// Keep defaults for empty config files.
	} else if opts.AllowUnknownFields {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	} else {
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	// Load API keys from environment if not set in config
	if len(cfg.Server.APIKeys) == 0 {
		if envKey := os.Getenv("ONESEC_API_KEY"); envKey != "" {
			cfg.Server.APIKeys = []string{envKey}
		}
	}

	// Load CORS origins from environment if set (comma-separated, appended to config values)
	if envCORS := os.Getenv("ONESEC_CORS_ORIGINS"); envCORS != "" {
		for _, origin := range strings.Split(envCORS, ",") {
			origin = strings.TrimSpace(origin)
			if origin != "" {
				cfg.Server.CORSOrigins = append(cfg.Server.CORSOrigins, origin)
			}
		}
	}

	// Load cloud dashboard API key from environment if not set in config
	if cfg.Cloud.APIKey == "" {
		if envKey := os.Getenv("ONESEC_CLOUD_API_KEY"); envKey != "" {
			cfg.Cloud.APIKey = envKey
			cfg.Cloud.Enabled = true
		}
	}
	if envURL := os.Getenv("ONESEC_CLOUD_API_URL"); envURL != "" {
		cfg.Cloud.APIURL = envURL
	}

	// Load Auth0 Token Vault config from environment
	if env := os.Getenv("AUTH0_DOMAIN"); env != "" {
		cfg.TokenVault.Auth0Domain = env
		cfg.TokenVault.Enabled = true
	}
	if env := os.Getenv("AUTH0_CLIENT_ID"); env != "" {
		cfg.TokenVault.Auth0ClientID = env
	}
	if env := os.Getenv("AUTH0_CLIENT_SECRET"); env != "" {
		cfg.TokenVault.Auth0ClientSecret = env
	}

	// Load Rust engine toggle from environment (ONESEC_RUST_ENGINE=true|false)
	if envRust := os.Getenv("ONESEC_RUST_ENGINE"); envRust != "" {
		cfg.RustEngine.Enabled = strings.EqualFold(envRust, "true") || envRust == "1"
	}

	// Load log level from environment (ONESEC_LOG_LEVEL=debug|info|warn|error)
	if envLog := os.Getenv("ONESEC_LOG_LEVEL"); envLog != "" {
		cfg.Logging.Level = strings.ToLower(strings.TrimSpace(envLog))
	}

	return cfg, nil
}

// SaveConfig writes the configuration to a YAML file.
func SaveConfig(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(path, data, ConfigFileMode)
}

// IsModuleEnabled checks if a module is enabled in the configuration.
func (c *Config) IsModuleEnabled(name string) bool {
	mod, ok := c.Modules[name]
	if !ok {
		return true
	}
	return mod.Enabled
}

// GetModuleSettings returns the settings map for a module.
func (c *Config) GetModuleSettings(name string) map[string]interface{} {
	mod, ok := c.Modules[name]
	if !ok || mod.Settings == nil {
		return map[string]interface{}{}
	}
	return mod.Settings
}

// GetModuleSetting returns a specific setting value for a module.
func (c *Config) GetModuleSetting(module, key string, defaultVal interface{}) interface{} {
	settings := c.GetModuleSettings(module)
	if val, ok := settings[key]; ok {
		return val
	}
	return defaultVal
}

// ParseSeverity converts a string to a Severity value.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return SeverityLow
	case "MEDIUM":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// LogLevel returns the parsed log level string.
func (c *Config) LogLevel() string {
	return strings.ToLower(c.Logging.Level)
}

// AuthEnabled returns true if API key authentication is configured.
func (c *Config) AuthEnabled() bool {
	return len(c.Server.APIKeys) > 0 || len(c.Server.ReadOnlyKeys) > 0
}

// ServerHostIsLoopback returns true when the REST API bind host is loopback.
func (c *Config) ServerHostIsLoopback() bool {
	return isLoopbackHost(c.Server.Host)
}

// OpenReadAllowed returns true when unauthenticated read-only endpoints may be
// served in no-key mode.
func (c *Config) OpenReadAllowed() bool {
	return c.Server.AllowUnauthenticatedRead || c.ServerHostIsLoopback()
}

// TLSEnabled returns true if TLS certificate and key are configured.
func (c *Config) TLSEnabled() bool {
	return c.Server.TLSCert != "" && c.Server.TLSKey != ""
}

// ValidateAPIKey checks if the provided key matches any configured API key.
// Uses constant-time comparison to prevent timing attacks.
// Returns "write" for full-access keys, "read" for read-only keys, "" for invalid.
func (c *Config) ValidateAPIKey(key string) string {
	for _, valid := range c.Server.APIKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(valid)) == 1 {
			return "write"
		}
	}
	for _, valid := range c.Server.ReadOnlyKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(valid)) == 1 {
			return "read"
		}
	}
	return ""
}

// Validate checks the configuration for common errors and returns a list of
// warnings and a list of errors. Errors are fatal; warnings are informational.
func (c *Config) Validate() (warnings []string, errs []string) {
	if _, err := NewManagementAccessPolicy(c.ManagementAccess); err != nil {
		errs = append(errs, err.Error())
	}
	// Server port
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Sprintf("server.port %d is out of range (1-65535)", c.Server.Port))
	}

	// TLS files
	if c.TLSEnabled() {
		if _, err := os.Stat(c.Server.TLSCert); err != nil {
			errs = append(errs, fmt.Sprintf("tls_cert file not found: %s", c.Server.TLSCert))
		}
		if _, err := os.Stat(c.Server.TLSKey); err != nil {
			errs = append(errs, fmt.Sprintf("tls_key file not found: %s", c.Server.TLSKey))
		}
	}

	// Syslog
	if c.Syslog.Enabled {
		if c.Syslog.Port <= 0 || c.Syslog.Port > 65535 {
			errs = append(errs, fmt.Sprintf("syslog.port %d is out of range (1-65535)", c.Syslog.Port))
		}
		switch c.Syslog.Protocol {
		case "udp", "tcp", "both":
			// valid
		default:
			errs = append(errs, fmt.Sprintf("syslog.protocol %q is invalid (use udp, tcp, or both)", c.Syslog.Protocol))
		}
	}

	// Bus port
	if c.Bus.Embedded && (c.Bus.Port <= 0 || c.Bus.Port > 65535) {
		errs = append(errs, fmt.Sprintf("bus.port %d is out of range (1-65535)", c.Bus.Port))
	}

	// CORS wildcard warning
	for _, o := range c.Server.CORSOrigins {
		if o == "*" {
			warnings = append(warnings, "cors_origins contains wildcard '*' — any origin can make cross-origin requests")
			break
		}
	}

	// Auth warning
	if !c.AuthEnabled() {
		if c.OpenReadAllowed() {
			warnings = append(warnings, "no api_keys or read_only_keys configured - API read endpoints run in open mode on a loopback or explicitly allowed bind; mutating endpoints are blocked")
		} else {
			warnings = append(warnings, "no api_keys or read_only_keys configured and API is bound to a non-loopback host - only /health is accessible until keys are configured or server.allow_unauthenticated_read is set")
		}
	}
	// Enforcement policy validation
	if c.Enforcement != nil && c.Enforcement.Enabled {
		validActions := map[string]bool{
			"block_ip": true, "kill_process": true, "quarantine_file": true,
			"drop_connection": true, "disable_user": true, "webhook": true,
			"command": true, "log_only": true,
		}
		for module, policy := range c.Enforcement.Policies {
			if policy.CooldownSeconds < 0 {
				errs = append(errs, fmt.Sprintf("enforcement.policies.%s.cooldown_seconds cannot be negative", module))
			}
			if policy.MaxActionsPerMin < 0 {
				errs = append(errs, fmt.Sprintf("enforcement.policies.%s.max_actions_per_min cannot be negative", module))
			}
			for i, action := range policy.Actions {
				if !validActions[action.Action] {
					errs = append(errs, fmt.Sprintf("enforcement.policies.%s.actions[%d].action %q is unknown", module, i, action.Action))
				}
			}
		}
		if c.Enforcement.Preset != "" {
			validPresets := map[string]bool{"safe": true, "lax": true, "balanced": true, "strict": true, "vps-agent": true}
			if !validPresets[c.Enforcement.Preset] {
				warnings = append(warnings, fmt.Sprintf("enforcement.preset %q is unknown (valid: safe, lax, balanced, strict, vps-agent)", c.Enforcement.Preset))
			}
		}
	}

	return warnings, errs
}

func envBool(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

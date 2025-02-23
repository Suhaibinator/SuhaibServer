package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration so we can implement custom
// YAML and JSON unmarshaling from a string like "5s".
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	// We'll unmarshal into a string first.
	var durationStr string
	if err := value.Decode(&durationStr); err != nil {
		return err
	}

	// Now parse the duration string (e.g. "5s", "500ms", etc.).
	parsed, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", durationStr, err)
	}
	d.Duration = parsed
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *Duration) UnmarshalJSON(data []byte) error {
	// We'll unmarshal into a string first.
	var durationStr string
	if err := json.Unmarshal(data, &durationStr); err != nil {
		return err
	}

	// Then parse the duration string using time.ParseDuration.
	parsed, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", durationStr, err)
	}
	d.Duration = parsed
	return nil
}

// Config can be unmarshaled from both YAML and JSON.
type Config struct {
	SniSniffer SniSnifferConfig `yaml:"SniSniffer" json:"SniSniffer"`
	Backends   []BackendConfig  `yaml:"Backends"   json:"Backends"`
	Port       string           `yaml:"Port"       json:"Port"`
	CertsPath  string           `yaml:"CertsPath"  json:"CertsPath"`
	LogLevel   string           `yaml:"LogLevel"   json:"LogLevel"`
}

// SniSnifferConfig now uses Duration instead of string for Timeout.
type SniSnifferConfig struct {
	MaxReadSize int      `yaml:"MaxReadSize" json:"MaxReadSize"`
	Timeout     Duration `yaml:"Timeout"     json:"Timeout"`
}

type MTLSPolicy struct {
	// If true, *every* request requires mTLS by default—unless
	// the request matches an exception below.
	// If false, no request requires mTLS by default—unless
	// it matches an exception below.
	Default bool `yaml:"Default" json:"Default"`

	// These are path prefixes for which we will *invert* the default.
	// e.g. if Default=true => these paths will *not* require mTLS
	// if Default=false => these paths *will* require mTLS.
	Paths []string `yaml:"Paths" json:"Paths"`

	// Same logic as Paths, but for query parameters: if any of these
	// query params are present, invert the default behavior.
	Queries []string `yaml:"Queries" json:"Queries"`
}

// Duration, SniSnifferConfig, MTLSPolicy types unchanged...
// (omitting for brevity)

type BackendConfig struct {
	Hostname string `yaml:"Hostname" json:"Hostname"`

	// If false, no mTLS is used at all (TLS only).
	// If true, we consult MTLSPolicy to decide if a given
	// path/query enforces mTLS or not.
	MTLSEnabled  bool        `yaml:"MtlsEnabled" json:"MtlsEnabled"`
	MTLSPolicy   *MTLSPolicy `yaml:"MtlsPolicy"  json:"MtlsPolicy"`
	TerminateTLS bool        `yaml:"TerminateTLS" json:"TerminateTLS"`

	// Note that we now allow just a filename, which we’ll resolve after parsing.
	TLSCertFile string `yaml:"TlsCertFile"  json:"TlsCertFile"`
	TLSKeyFile  string `yaml:"TlsKeyFile"   json:"TlsKeyFile"`
	RootCAFile  string `yaml:"RootCAFile"   json:"RootCAFile"`

	OriginServer string `yaml:"OriginServer" json:"OriginServer"`
	OriginPort   string `yaml:"OriginPort"   json:"OriginPort"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config

	// Attempt YAML unmarshal first
	yamlErr := yaml.Unmarshal(data, &cfg)
	if yamlErr != nil {
		// If YAML fails, we try JSON
		jsonErr := json.Unmarshal(data, &cfg)
		if jsonErr != nil {
			return nil, fmt.Errorf(
				"could not parse file as YAML or JSON. YAML error: %v; JSON error: %v",
				yamlErr, jsonErr,
			)
		}
	}

	if cfg.Port == "" {
		cfg.Port = "443"
	}
	// At this point, cfg is loaded from either YAML or JSON.
	// Let's fix up file paths by prepending /etc/certs if they're not absolute.
	var certsPath string
	if cfg.CertsPath == "" {
		certsPath = "/etc/certs"
	} else {
		certsPath = cfg.CertsPath
	}
	cfg.resolveCertPaths(certsPath)

	return &cfg, nil
}

// resolveCertPaths updates each BackendConfig so that if the user-provided
// TLSCertFile, TLSKeyFile, or RootCAFile is not an absolute path,
// we prepend the given baseDir (e.g. "/etc/certs").
func (c *Config) resolveCertPaths(baseDir string) {
	for i, b := range c.Backends {
		if b.TLSCertFile != "" && !filepath.IsAbs(b.TLSCertFile) {
			c.Backends[i].TLSCertFile = filepath.Join(baseDir, b.TLSCertFile)
		}
		if b.TLSKeyFile != "" && !filepath.IsAbs(b.TLSKeyFile) {
			c.Backends[i].TLSKeyFile = filepath.Join(baseDir, b.TLSKeyFile)
		}
		if b.RootCAFile != "" && !filepath.IsAbs(b.RootCAFile) {
			c.Backends[i].RootCAFile = filepath.Join(baseDir, b.RootCAFile)
		}
	}
}

package config

import (
	"encoding/json"
	"fmt"
	"os"
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
}

// SniSnifferConfig now uses Duration instead of string for Timeout.
type SniSnifferConfig struct {
	MaxReadSize int      `yaml:"MaxReadSize" json:"MaxReadSize"`
	Timeout     Duration `yaml:"Timeout"     json:"Timeout"`
}

// The rest of your backend config is unchanged
type BackendConfig struct {
	HostName     string             `yaml:"HostName"     json:"HostName"`
	TerminateTLS bool               `yaml:"TerminateTLS" json:"TerminateTLS"`
	MTLSEnabled  bool               `yaml:"MTLSEnabled"  json:"MTLSEnabled"`
	MTLSEnforce  *MTLSEnforceConfig `yaml:"MTLSEnforce"  json:"MTLSEnforce"`

	TLSCertFile  string `yaml:"TLSCertFile"  json:"TLSCertFile"`
	TLSKeyFile   string `yaml:"TLSKeyFile"   json:"TLSKeyFile"`
	RootCAFile   string `yaml:"RootCAFile"   json:"RootCAFile"`
	OriginServer string `yaml:"OriginServer" json:"OriginServer"`
	OriginPort   string `yaml:"OriginPort"   json:"OriginPort"`
}

type MTLSEnforceConfig struct {
	Paths   []string `yaml:"Paths"   json:"Paths"`
	Queries []string `yaml:"Queries" json:"Queries"`
}

// LoadConfig attempts to parse the given file as YAML first,
// then JSON if YAML fails.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config

	// Attempt YAML unmarshal first
	if yamlErr := yaml.Unmarshal(data, &cfg); yamlErr == nil {
		// Success with YAML
		return &cfg, nil
	} else {
		// If YAML fails, we try JSON
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr == nil {
			return &cfg, nil
		} else {
			// Both failed
			return nil, fmt.Errorf("could not parse file as YAML or JSON. YAML error: %v; JSON error: %v", yamlErr, jsonErr)
		}
	}
}

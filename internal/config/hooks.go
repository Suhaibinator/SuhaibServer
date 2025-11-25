package config

import (
	"fmt"
	"strings"

	"github.com/Suhaibinator/SuhaibServer/sdk/hooks"
)

type HookMatchConfig struct {
	Host       string   `yaml:"host" json:"host"`
	PathPrefix string   `yaml:"path_prefix" json:"path_prefix"`
	Methods    []string `yaml:"methods" json:"methods"`
}

type HookConfig struct {
	Name    string          `yaml:"name" json:"name"`
	Kind    hooks.Kind      `yaml:"kind" json:"kind"`
	Match   HookMatchConfig `yaml:"match" json:"match"`
	Timeout Duration        `yaml:"timeout" json:"timeout"`
}

type BackendHooks struct {
	OnRequestReceived  []string `yaml:"on_request_received" json:"on_request_received"`
	OnRequestCompleted []string `yaml:"on_request_completed" json:"on_request_completed"`
}

type BackendHookPlan struct {
	Request    []hooks.ResolvedHook
	Completion []hooks.ResolvedHook
}

func (c *Config) ResolveBackendHooks() (map[string]BackendHookPlan, error) {
	definitions := make(map[string]HookConfig)
	for _, hc := range c.Hooks {
		if hc.Name == "" {
			return nil, fmt.Errorf("hook definition missing name")
		}
		if _, exists := definitions[hc.Name]; exists {
			return nil, fmt.Errorf("duplicate hook definition: %s", hc.Name)
		}
		definitions[hc.Name] = hc
	}

	plans := make(map[string]BackendHookPlan)
	for _, backendCfg := range c.Backends {
		requestHooks, err := resolveHookNames(backendCfg.Hooks.OnRequestReceived, definitions, hooks.OnRequestReceived)
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", backendCfg.Hostname, err)
		}
		completionHooks, err := resolveHookNames(backendCfg.Hooks.OnRequestCompleted, definitions, hooks.OnRequestCompleted)
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", backendCfg.Hostname, err)
		}
		plans[backendCfg.Hostname] = BackendHookPlan{
			Request:    requestHooks,
			Completion: completionHooks,
		}
	}
	return plans, nil
}

func resolveHookNames(names []string, definitions map[string]HookConfig, expectedKind hooks.Kind) ([]hooks.ResolvedHook, error) {
	resolved := make([]hooks.ResolvedHook, 0, len(names))
	for _, name := range names {
		def, ok := definitions[name]
		if !ok {
			return nil, fmt.Errorf("hook %q not defined", name)
		}
		if def.Kind != expectedKind {
			return nil, fmt.Errorf("hook %q has kind %s, expected %s", name, def.Kind, expectedKind)
		}
		reg, found := hooks.Lookup(name)
		if !found {
			return nil, fmt.Errorf("hook %q not registered", name)
		}
		matcher := hooks.Matcher{
			Host:       def.Match.Host,
			PathPrefix: def.Match.PathPrefix,
			Methods:    normalizeMethods(def.Match.Methods),
		}
		resolved = append(resolved, hooks.ResolvedHook{
			Registration: reg,
			Matcher:      matcher,
			Timeout:      def.Timeout.Duration,
		})
	}
	hooks.SortByPriority(resolved)
	return resolved, nil
}

func normalizeMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, strings.ToUpper(m))
	}
	return out
}

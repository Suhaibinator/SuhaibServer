package config

import (
	"context"
	"testing"

	"github.com/Suhaibinator/SuhaibServer/sdk/hooks"
)

func TestResolveBackendHooksErrorsOnMissingRegistration(t *testing.T) {
	hooks.ResetRegistryForTesting()
	cfg := Config{
		Hooks: []HookConfig{{
			Name: "missing",
			Kind: hooks.OnRequestReceived,
		}},
		Backends: []BackendConfig{{
			Hostname: "api.example.com",
			Hooks:    BackendHooks{OnRequestReceived: []string{"missing"}},
		}},
	}

	if _, err := cfg.ResolveBackendHooks(); err == nil {
		t.Fatalf("expected error when hook not registered")
	}
}

func TestResolveBackendHooksSortsByPriority(t *testing.T) {
	hooks.ResetRegistryForTesting()
	_ = hooks.Register(hooks.Registration{
		Name:     "late",
		Kind:     hooks.OnRequestReceived,
		Handler:  hooks.RequestHook(func(context.Context, hooks.RequestCtx) error { return nil }),
		Priority: 10,
	})
	_ = hooks.Register(hooks.Registration{
		Name:     "early",
		Kind:     hooks.OnRequestReceived,
		Handler:  hooks.RequestHook(func(context.Context, hooks.RequestCtx) error { return nil }),
		Priority: 1,
	})

	cfg := Config{
		Hooks: []HookConfig{
			{Name: "late", Kind: hooks.OnRequestReceived},
			{Name: "early", Kind: hooks.OnRequestReceived},
		},
		Backends: []BackendConfig{{
			Hostname: "api.example.com",
			Hooks:    BackendHooks{OnRequestReceived: []string{"late", "early"}},
		}},
	}

	plan, err := cfg.ResolveBackendHooks()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hooks := plan["api.example.com"].Request
	if len(hooks) != 2 {
		t.Fatalf("expected 2 hooks, got %d", len(hooks))
	}
	if hooks[0].Registration.Name != "early" {
		t.Fatalf("expected priority order to place early first, got %s", hooks[0].Registration.Name)
	}
}

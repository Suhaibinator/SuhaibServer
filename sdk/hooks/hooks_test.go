package hooks

import (
	"context"
	"testing"
)

func TestSortByPriority(t *testing.T) {
	defer resetRegistryForTesting()

	low := Registration{Name: "low", Kind: OnRequestReceived, Handler: RequestHook(func(context.Context, RequestCtx) error { return nil }), Priority: 10}
	high := Registration{Name: "high", Kind: OnRequestReceived, Handler: RequestHook(func(context.Context, RequestCtx) error { return nil }), Priority: 1}

	hooks := []ResolvedHook{{Registration: low}, {Registration: high}}
	SortByPriority(hooks)

	if hooks[0].Registration.Name != "high" {
		t.Fatalf("expected high priority hook first, got %s", hooks[0].Registration.Name)
	}
}

func TestRegisterMissingName(t *testing.T) {
	defer resetRegistryForTesting()

	err := Register(Registration{Kind: OnRequestReceived, Handler: RequestHook(func(context.Context, RequestCtx) error { return nil })})
	if err == nil {
		t.Fatalf("expected error for missing name")
	}
}

func TestLookupFailsForUnknown(t *testing.T) {
	defer resetRegistryForTesting()

	if _, ok := Lookup("does-not-exist"); ok {
		t.Fatalf("expected Lookup to fail for unknown hook")
	}
}

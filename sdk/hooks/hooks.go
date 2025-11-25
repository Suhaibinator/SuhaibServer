package hooks

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type Kind string

const (
	OnRequestReceived  Kind = "on_request_received"
	OnRequestCompleted Kind = "on_request_completed"
)

type ClientCert struct {
	Leaf        *x509.Certificate
	Chain       []*x509.Certificate
	Fingerprint string
}

type RequestCtx struct {
	Req        *http.Request
	Host       string
	Path       string
	TraceID    string
	ClientIP   string
	Meta       map[string]string
	ClientCert *ClientCert
}

type ResponseCtx struct {
	ReqCtx  RequestCtx
	Status  int
	Headers http.Header
	Err     error
	Latency time.Duration
}

type RequestHook func(ctx context.Context, rc RequestCtx) error

type CompletionHook func(ctx context.Context, rc ResponseCtx) error

type Registration struct {
	Name     string
	Kind     Kind
	Handler  any
	Priority int
}

type Matcher struct {
	Host       string
	PathPrefix string
	Methods    []string
}

func (m Matcher) Matches(rc RequestCtx) bool {
	if m.Host != "" && !strings.EqualFold(m.Host, rc.Host) {
		return false
	}
	if m.PathPrefix != "" && !strings.HasPrefix(rc.Path, m.PathPrefix) {
		return false
	}
	if len(m.Methods) > 0 && rc.Req != nil {
		method := strings.ToUpper(rc.Req.Method)
		allowed := false
		for _, mth := range m.Methods {
			if method == strings.ToUpper(mth) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

type ResolvedHook struct {
	Registration Registration
	Matcher      Matcher
	Timeout      time.Duration
}

func SortByPriority(hooks []ResolvedHook) {
	sort.SliceStable(hooks, func(i, j int) bool {
		return hooks[i].Registration.Priority < hooks[j].Registration.Priority
	})
}

var (
	regMu     sync.RWMutex
	registry  = make(map[string]Registration)
	errNoName = errors.New("hook name is required")
)

func Register(reg Registration) error {
	if reg.Name == "" {
		return errNoName
	}

	switch reg.Kind {
	case OnRequestReceived:
		if _, ok := reg.Handler.(RequestHook); !ok {
			return errors.New("handler must be RequestHook for on_request_received")
		}
	case OnRequestCompleted:
		if _, ok := reg.Handler.(CompletionHook); !ok {
			return errors.New("handler must be CompletionHook for on_request_completed")
		}
	default:
		return errors.New("unknown hook kind")
	}

	regMu.Lock()
	defer regMu.Unlock()
	if _, exists := registry[reg.Name]; exists {
		return errors.New("hook already registered")
	}
	registry[reg.Name] = reg
	return nil
}

func Lookup(name string) (Registration, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	reg, ok := registry[name]
	return reg, ok
}

func resetRegistryForTesting() {
	regMu.Lock()
	defer regMu.Unlock()
	registry = make(map[string]Registration)
}

// ResetRegistryForTesting clears the registry; meant for use in tests.
func ResetRegistryForTesting() {
	resetRegistryForTesting()
}

func Registered() []Registration {
	regMu.RLock()
	defer regMu.RUnlock()
	res := make([]Registration, 0, len(registry))
	for _, r := range registry {
		res = append(res, r)
	}
	return res
}

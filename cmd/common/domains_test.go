package common

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/domainr/dnsr"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

func TestCheckUrlSendsPluginUserAgent(t *testing.T) {
	AppVersion = "test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.UserAgent(), "Go-http-client") {
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		if r.UserAgent() != "fleetssl-cpanel/test" {
			t.Errorf("unexpected User-Agent %q", r.UserAgent())
		}
		w.Write([]byte("token"))
	}))
	defer srv.Close()

	if err := checkUrl(srv.URL, "token"); err != nil {
		t.Fatalf("checkUrl failed: %v", err)
	}
}

func TestIsDomainAccessibleRetriesTransientDNSMiss(t *testing.T) {
	origResolve, origDelay := resolveIterative, dnsLookupRetryDelay
	defer func() { resolveIterative, dnsLookupRetryDelay = origResolve, origDelay }()
	dnsLookupRetryDelay = 0

	calls := 0
	resolveIterative = func(name string) dnsr.RRs {
		calls++
		return nil // always empty: every attempt misses
	}
	err := IsDomainAccessible("u", DomainEntry{Domain: "example.test"}, cpanel.CpanelApi{})
	if err == nil || !strings.Contains(err.Error(), "gave no results") {
		t.Fatalf("want DNS error, got %v", err)
	}
	if calls != dnsLookupAttempts {
		t.Fatalf("want %d attempts, got %d", dnsLookupAttempts, calls)
	}

	calls = 0
	resolveIterative = func(name string) dnsr.RRs {
		calls++
		if calls < 2 {
			return nil // first walk misses
		}
		return dnsr.RRs{{Name: name, Type: "A", Value: "192.0.2.1"}}
	}
	// DNS now succeeds; the later file-creation step fails in tests, which
	// proves we got past the DNS check on the retry.
	err = IsDomainAccessible("u", DomainEntry{Domain: "example.test", DocumentRoot: t.TempDir()}, cpanel.CpanelApi{})
	if err != nil && strings.Contains(err.Error(), "gave no results") {
		t.Fatalf("retry did not recover: %v", err)
	}
	if calls != 2 {
		t.Fatalf("want 2 attempts, got %d", calls)
	}
}

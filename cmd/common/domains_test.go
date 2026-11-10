package common

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

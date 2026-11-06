package daemon

import (
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/letsencrypt-cpanel/cpanelgo"
	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	"math/big"
	"reflect"
	"sort"
	"testing"
	"time"
)

func mustParseTime(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestShouldRunRenewals(tt *testing.T) {
	table := []struct {
		now      time.Time
		days     []string
		times    [2]int
		expected bool
	}{
		{
			mustParseTime("2016-12-18 09:00:00"),
			[]string{"Sunday"},
			[2]int{9, 17},
			true,
		},
		{
			mustParseTime("2016-12-18 09:00:00"),
			[]string{"Monday"},
			[2]int{0, 0},
			false,
		},
		{
			mustParseTime("2016-12-18 09:00:00"),
			[]string{"Sunday"},
			[2]int{10, 17},
			false,
		},
	}

	for _, t := range table {
		config.RenewalDaysOfWeek = t.days
		config.RenewalTimeOfDay = &(t.times)

		if res := shouldRunRenewals(t.now); res != t.expected {
			tt.Fatalf("Wanted %v, got %v for %#v", res, t.expected, t)
		}
	}
}

func TestPrepareRenewalCertificate(t *testing.T) {
	const root = "example.test"
	names := []string{root, "mail.example.test", "webmail.example.test", "www.example.test", "autodiscover.example.test", "alias.test"}
	group := common.DomainList{}
	for _, name := range names {
		group.AddDomain(name, "Alias", "/public_html", "test", root)
	}
	original := &common.NVDataDomainCerts{Domain: root, AltNames: names[1:], DomainKey: "key", PreferredIssuer: "issuer"}
	for _, method := range []string{"", "http-01", "dns-01"} {
		t.Run("method="+method, func(t *testing.T) {
			cert := *original
			cert.ChallengeMethod = method
			checks := 0
			prepared, err := prepareRenewalCertificate(&cert, group, func(entry common.DomainEntry) error {
				checks++
				if entry.Domain == "mail.example.test" || entry.Domain == "autodiscover.example.test" || entry.Domain == "www.example.test" || entry.Domain == "alias.test" {
					return errors.New("DCV failed")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if method == "dns-01" {
				if checks != 0 || !reflect.DeepEqual(prepared, &cert) {
					t.Fatal("DNS renewal changed or used HTTP DCV")
				}
				return
			}
			if checks != len(names) || !reflect.DeepEqual(prepared.AltNames, []string{"webmail.example.test"}) {
				t.Fatalf("checks=%d names=%v", checks, prepared.AltNames)
			}
			if !reflect.DeepEqual(cert.AltNames, names[1:]) || prepared.DomainKey != cert.DomainKey || prepared.PreferredIssuer != cert.PreferredIssuer {
				t.Fatal("existing certificate mutated or settings lost")
			}
			// Simulate the issued names and an nvdata round trip before the next renewal.
			raw, err := json.Marshal(prepared)
			if err != nil {
				t.Fatal(err)
			}
			var stored common.NVDataDomainCerts
			if err := json.Unmarshal(raw, &stored); err != nil {
				t.Fatal(err)
			}
			grouped, leftovers, err := common.GroupNVDataDomains(map[string]*common.NVDataDomainCerts{root: &stored}, group)
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("grouping: %v %v", leftovers, err)
			}
			restored, err := prepareRenewalCertificate(&stored, grouped[root], func(common.DomainEntry) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			want := append([]string{}, names[1:]...)
			sort.Strings(want)
			sort.Strings(restored.AltNames)
			if !reflect.DeepEqual(restored.AltNames, want) {
				t.Fatalf("restored names=%v want=%v", restored.AltNames, want)
			}
		})
	}
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing root", false: "failed root"}[missing], func(t *testing.T) {
			rootGroup := common.DomainList{}
			if !missing {
				rootGroup[root] = group[root]
			}
			checks := 0
			_, err := prepareRenewalCertificate(original, rootGroup, func(common.DomainEntry) error { checks++; return errors.New("root failed") })
			if err == nil || checks > 1 {
				t.Fatalf("root failure: err=%v checks=%d", err, checks)
			}
		})
	}
}

func TestCertificateCoversRenewalNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.test", "webmail.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if !certificateCoversNames(certPEM, cert.DNSNames) {
		t.Fatal("unchanged passing names should allow reuse")
	}
	if certificateCoversNames(certPEM, append(cert.DNSNames, "mail.example.test")) {
		t.Fatal("recovered mail name must prevent reuse")
	}
	if certificateCoversNames("invalid PEM", cert.DNSNames) {
		t.Fatal("invalid certificate must prevent reuse")
	}
}

func TestRenewalCandidatesDoNotMutateSavedNames(t *testing.T) {
	cert := &common.NVDataDomainCerts{Domain: "example.test", AltNames: []string{"webmail.example.test"}, RenewalNames: []string{"mail.example.test"}}
	data := &common.NVDataAccount{Certs: map[string]*common.NVDataDomainCerts{cert.Domain: cert}}
	group := common.DomainList{}
	for _, name := range []string{cert.Domain, "mail.example.test", "webmail.example.test"} {
		group.AddDomain(name, "Alias", "/public_html", "test", cert.Domain)
	}
	candidate, err := getExistingCertificateFromNVData(cert.Domain, group, data)
	if err != nil {
		t.Fatal(err)
	}
	if candidate == cert || !reflect.DeepEqual(candidate.AltNames, cert.AltNames) || !reflect.DeepEqual(cert.AltNames, []string{"webmail.example.test"}) {
		t.Fatal("saved names changed while preparing renewal")
	}
}

// Embed the interface so any unexpected API call fails the test.
type renewalGateway struct {
	cpanelgo.ApiGateway
	certID, keyID string
	calls         []string
}

func (g *renewalGateway) UAPI(module, function string, args cpanelgo.Args, out interface{}) error {
	g.calls = append(g.calls, function)
	switch function {
	case "install_ssl":
		return json.Unmarshal([]byte(fmt.Sprintf(`{"status":1,"data":{"cert_id":%q,"key_id":%q}}`, g.certID, g.keyID)), out)
	case "delete_cert", "delete_key":
		g.calls[len(g.calls)-1] += ":" + args["id"].(string)
		return json.Unmarshal([]byte(`{"status":1}`), out)
	default:
		return fmt.Errorf("unexpected API call: %s.%s", module, function)
	}
}

func renewalTestCertificate(t *testing.T, names []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), DNSNames: names, NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestReusedCertificateCleanup(t *testing.T) {
	savedConfig := config
	defer func() { config = savedConfig }()
	config.DeferredRestarts = false
	for _, tc := range []struct {
		name, oldCert, oldKey, newCert, newKey string
		want                                   []string
	}{
		{"changed IDs", "old-cert", "old-key", "new-cert", "new-key", []string{"install_ssl", "delete_cert:old-cert", "delete_key:old-key"}},
		{"same IDs", "cert", "key", "cert", "key", []string{"install_ssl"}},
		{"same key", "old-cert", "key", "new-cert", "key", []string{"install_ssl", "delete_cert:old-cert"}},
		{"empty old IDs", "", "", "new-cert", "new-key", []string{"install_ssl"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := "example.test"
			cert := &common.NVDataDomainCerts{Domain: root, DomainCert: renewalTestCertificate(t, []string{root}), CertExpiry: time.Now().Add(365 * 24 * time.Hour).Unix(), ChallengeMethod: "dns-01", CertId: tc.oldCert, KeyId: tc.oldKey}
			data := &common.NVDataAccount{Certs: map[string]*common.NVDataDomainCerts{root: cert}}
			group := common.DomainList{}
			group.AddDomain(root, "Main", "/public_html", "test", root)
			gateway := &renewalGateway{certID: tc.newCert, keyID: tc.newKey}
			cp := cpanel.CpanelApi{Api: cpanelgo.NewApi(gateway)}
			resultCert, result, err := processRenewalForAccountDomain(root, "test", group, data, cp, false, false)
			if err != nil || result != ResultRenewalReinstall {
				t.Fatalf("result=%v err=%v", result, err)
			}
			if !reflect.DeepEqual(gateway.calls, tc.want) {
				t.Fatalf("calls=%v want=%v", gateway.calls, tc.want)
			}
			if resultCert.CertId != tc.newCert || resultCert.KeyId != tc.newKey {
				t.Fatal("new IDs lost")
			}
			if cert.CertId != tc.oldCert || cert.KeyId != tc.oldKey {
				t.Fatal("saved IDs mutated")
			}
		})
	}
}

func TestCertificateCoversWildcardRenewalNames(t *testing.T) {
	certPEM := renewalTestCertificate(t, []string{"example.test", "*.example.test"})
	for _, tc := range []struct {
		name  string
		names []string
		want  bool
	}{
		{"overlapping explicit name", []string{"example.test", "*.example.test", "mail.example.test"}, true},
		{"wildcard does not cover deeper name", []string{"example.test", "*.example.test", "deep.mail.example.test"}, false},
		{"wildcard does not cover other domain", []string{"example.test", "*.example.test", "other.test"}, false},
		{"wildcard does not cover apex", []string{"example.test", "*.example.test"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pem := certPEM
			if tc.name == "wildcard does not cover apex" {
				pem = renewalTestCertificate(t, []string{"*.example.test"})
			}
			if got := certificateCoversNames(pem, tc.names); got != tc.want {
				t.Fatalf("coverage=%v want=%v", got, tc.want)
			}
		})
	}
}

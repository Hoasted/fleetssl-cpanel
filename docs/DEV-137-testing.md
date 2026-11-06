# DEV-137: renewal DCV and recovery verification

## Local checks

The repository targets Go 1.19 and its build image uses Go 1.20. An isolated Linux Go 1.20.14 container can run:

```sh
go test ./cmd/...
go vet ./cmd/...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/fleetssl-dev137 cmd/letsencrypt.go
```

`TestPrepareRenewalCertificate` checks optional-name failures (mail, www, autodiscover, alias), retention of working webmail, primary-name failure/missing primary, the default/explicit HTTP method, unchanged DNS-01 behavior, and recovery after an NVData JSON round trip and regrouping. These are deterministic tests with a substituted DCV result; they do not prove real cPanel, DNS, HTTP, or ACME interoperability.

## Isolated cPanel acceptance test (not executed)

Use a disposable cPanel VM/account, controlled public DNS and a test domain. This needs separate authorization and must not use a customer account. Let’s Encrypt staging still requires real validation; DNS and port 80 must reach the lab. MX alone is not the criterion: the existing AutoSSL check requires a DNS record and the expected HTTP challenge file.

1. Build/install the candidate only in the lab. Snapshot the VM first. For persisted issuance tests, create `/etc/letsencrypt-cpanel.use-staging` **before starting the daemon**, then restart that lab daemon. `cmd/common/consts.go` selects the staging endpoint and CA bundle at process startup. Keep the lab on staging throughout; its certificates are not publicly trusted.
2. Through the plugin, issue an HTTP-01 certificate for the root, mail, www, webmail, an alias and cPanel subdomains. Record actual SANs and the account's NVData candidate list. Include a separate DNS-01/wildcard fixture for regression coverage.
3. Leave the root and webmail pointing at the lab; remove mail's address record, point autodiscover at an external CNAME, and make www/the alias fail HTTP validation. Wait for DNS caches to expire. From the lab, run:

   ```sh
   /opt/fleetssl-cpanel/letsencrypt.live.cgi ssl --user LABUSER renew --virtualhost example.test --dry-run
   ```

   Replace `LABUSER` and `example.test` with the lab account and public domain. Confirm omission logs for each failing name, staging issuance success and continued inclusion of root/webmail. Dry-run bypasses the expiry gate; `--force` is unnecessary. Dry-run creates temporary probe/challenge files and contacts cPanel/ACME, but skips installation and NVData persistence.
4. Repeat without `--dry-run`, adding `--force`, **only on the staging-configured lab daemon**. This installs a staging certificate, changes NVData, removes the old cPanel certificate/key and can restart Apache/send configured notifications. Inspect the installed certificate SANs: root/webmail remain, failed names are absent. NVData `renewal_names` must retain all eligible original candidates while `alt_names` records issued names.
5. Repeat with the root failing DCV. Expect renewal failure before ACME issuance; the previously installed certificate and saved names must remain intact.
6. Restore mail and the other skipped names. Run an ordinary scoped renewal (no force/dry-run) while the staging certificate still has plenty of validity. Confirm missing SANs trigger issuance despite the certificate reuse shortcut, the SANs return and NVData survives a daemon restart. Also verify the scheduled renewal loop on the lab; it uses the same per-account path.
7. Keep a name failing across two ordinary runs. Verify no repeated ACME issuance while the valid stored certificate covers all passing names. If the same certificate is already installed on the root and every reuse target, verify there are no install/delete calls, restart requests, renewal hooks, renewal reports or success mail. Remove a reuse target installation and verify reinstall still occurs.
8. Recheck the DNS-01/wildcard fixture: no HTTP preflight is added, and its existing DNS challenge flow still works. Explicitly reissuing a certificate replaces the requested selection; names never selected or already removed by earlier versions are not discovered by the new candidate field.

A dry-run alone cannot verify persistence or installation. Certificate reuse, privilege-dropped probe file creation, actual cPanel API behavior and proxy routing need the lab checks above. No server, DNS, RPM, Ansible, or Linear mutation is part of the local preparation.

## Sources and alternatives

- [Let’s Encrypt staging environment](https://letsencrypt.org/docs/staging-environment/): use staging for client testing; certificates use untrusted roots and separate rate limits.
- [Let’s Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/): HTTP-01 validates the challenge URL over port 80; DNS-01 validates TXT records and supports wildcards.
- [Pebble](https://github.com/letsencrypt/pebble): useful for ACME client tests, but this fork currently hardcodes production/staging URLs. Adding endpoint configuration and a fake cPanel/privilege boundary would broaden this change; use the real staging lab first.
- Repository evidence: `cmd/clapi/ssl.go` (CLI flags), `cmd/common/consts.go` (staging marker), `cmd/common/domains.go` (`IsDomainAccessible`), `cmd/common/letsencrypt.go` (ACME challenges), `cmd/daemon/renewal.go` (state/install/reuse gates), `Makefile`/`Dockerfile` (build/package requirements).

RPM packaging additionally needs Ruby/fpm, rpm tooling, gawk and dos2unix. `make rpm` builds both RPM and DEB. The supplied Dockerfile installs unpinned packaging tools; no package was built or deployed for this preparation.

## Local results (2026-11-05)

- `go test ./cmd/...`: passed, including the new renewal/recovery, stored-name and certificate-coverage regressions.
- Linux amd64 build: passed with CGO disabled.
- `go vet ./cmd/...`: blocked by the existing `cmd/daemon/daemon.go:62` unbuffered `os.Signal` channel passed to `signal.Notify`; confirmed present in the base revision, unchanged here.
- `git diff --check`: passed.
- Environment: official `golang:1.20.14-alpine` image, digest `sha256:e47f121850f4e276b2b210c56df3fda9191278dd84a3a442bfe0b09934462a8f`. No host Go installation or new Go dependencies.
- No live cPanel/ACME test, RPM build, Ansible update, deployment, push, PR or Linear write was performed.


## Local follow-up checks (2026-11-06)

- Cleanup captures old certificate/key IDs before installation and deletes only IDs that differ from the returned installed IDs. Fake cPanel gateway tests cover changed, unchanged, partially unchanged and empty old IDs through the real renewal reuse path.
- Certificate coverage removes wildcard-overlapped candidates using the existing issuance helper. Tests cover overlap, deeper names, other domains and the apex.
- Already-installed certificates produce an unchanged result when the identical decoded leaf is present on the root and every reuse target, using the existing unrevoked installed-host snapshot. The caller skips renewal hooks, reports, mail and certificate saving for that result. Missing/malformed host data falls back to installation.
- Repeated-run tests exercise the real per-domain renewal function with a fake cPanel gateway and no ACME credentials. Missing reuse targets still get installation; coverage tests still reject recovered names missing from the old certificate.
- DNS-01 propagation behavior is unchanged. Checking the last record can be a useful proxy when updates propagate together; it is not evidence that every challenge record is visible.

- A loopback-only fake ACME endpoint verifies the unchanged case makes no directory request, while a recovered name, forced renewal, dry-run and expiry still enter issuance. The endpoint deliberately rejects at directory discovery; this does not test a completed ACME order.
- Final command-package tests and Linux amd64 build passed after all three fixes. The existing signal-channel vet finding remains outside this change.

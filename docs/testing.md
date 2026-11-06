# Testing

## Where tests belong

Keep Go tests beside the code they exercise, in files named `<subject>_test.go`:

| Location | Coverage |
| --- | --- |
| `cmd/common/*_test.go` | Shared domain, certificate and ACME helpers |
| `cmd/daemon/*_test.go` | Renewal decisions, account state, cPanel calls and daemon behavior |
| `cmd/cgi/cpanelcgi/*_test.go` | cPanel UI actions and request handling |
| `cmd/cgi/*_test.go` | CGI entry points and shared CGI behavior |

Use the surrounding package convention, such as `package daemon`, when testing internal functions. Name tests `Test<Behavior>` and give table-driven subtests names that explain the scenario. Store reusable synthetic fixture files under the package's `testdata/` directory when inline values would be hard to read.

The fork under `internal/github.com/kardianos/service` is a separate Go module. Root-module test commands do not run its tests; run them separately from that directory when changing that fork.

## Writing tests

Structure each test around a starting state, one action and observable results:

1. Set up only the domains, certificate, account state or configuration the scenario needs.
2. Call the real function under test. Substitute external systems at their boundary rather than replacing the decision being tested.
3. Assert the returned result and relevant side effects: certificate names, persisted state, API calls, deleted IDs or absence of work.

For a bug fix, add a case that fails with the old behavior. Use a table when the same operation needs several inputs, such as changed versus unchanged certificate IDs. For stateful behavior, run the operation twice and verify the second run does not repeat unnecessary work. Where persistence matters, serialize and reload state before the next action.

Useful existing examples in `cmd/daemon/renewal_test.go`:

- `TestPrepareRenewalCertificate`: inject DCV results, check primary/optional names and round-trip account data through JSON.
- `TestReusedCertificateCleanup`: use a fake cPanel gateway and assert the actual install/delete calls and IDs.
- `TestInstalledCertificateSkipsRepeatedInstallation`: check repeated runs and missing installation targets.
- `TestRenewalEligibilityIgnoresOmittedNames`: verify omitted candidates do not schedule renewal, while expiring or missing issued names still do.
- `TestHealthyHTTPRenewalDoesNotProbeOmittedNames`: verify healthy certificates and installation repairs avoid HTTP probes.
- `TestUnchangedCertificateDoesNotSuppressRequiredIssuance`: use a loopback HTTP server to distinguish skipping issuance from entering it.

Use `t.Helper()` for fixture builders, `t.TempDir()` for new temporary-file fixtures, and `t.Cleanup()` to restore changed state. Existing tests change package globals such as configuration, database handles and ACME URLs; restore them and do not use `t.Parallel()` around shared state.

Keep routine tests independent of public DNS, real cPanel accounts and external ACME servers. Use `httptest.NewServer` for HTTP behavior and a fake `cpanelgo.ApiGateway` for cPanel calls. Fail on unexpected calls. Generate disposable certificate/key fixtures; do not use customer data or real credentials.

A fake ACME directory that rejects a request proves the code entered issuance, not that it can complete an ACME order. Likewise, matching certificate names does not prove installation on a virtual host. State the boundary each test verifies.

## Running local checks

Run from the repository root. `go.mod` declares Go 1.19 and the build Dockerfile uses Go 1.20. Linux is the preferred verification environment because production uses Linux and file/privilege behavior has platform-specific implementations.

```sh
# All application packages, bypassing cached test results.
go test -count=1 ./cmd/...

# Focus on one behavior and show individual scenarios.
go test -count=1 -v ./cmd/daemon -run '^TestReusedCertificateCleanup$'

# Compile the production target without installing or running it.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/fleetssl-test cmd/letsencrypt.go

# Static analysis, separate from the tests/build.
go vet ./cmd/...
```

`make test` currently runs only `go test -v ./cmd/daemon/`; use `go test ./cmd/...` for all application packages.

If Go is not installed on the host, the following runs the tests and Linux build in the official Go image used for local verification. Dependencies are downloaded into the disposable container; the repository is bind-mounted so tests can create their temporary files.

```sh
docker run --rm \
  -v "$PWD:/src" -w /src \
  golang:1.20.14-alpine@sha256:e47f121850f4e276b2b210c56df3fda9191278dd84a3a442bfe0b09934462a8f \
  sh -c 'go test -count=1 ./cmd/... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/fleetssl-test cmd/letsencrypt.go'
```

This pins the repository's older toolchain for reproducibility; it is not a recommendation to use that Go version for new projects. Building here does not export a binary from the container or build an RPM.

Known static-analysis finding: `cmd/daemon/daemon.go` passes an unbuffered signal channel to `signal.Notify`. Report this separately from test/build results until it is fixed; do not describe the entire check suite as passing when vet fails.

## GitHub Actions

`.github/workflows/tests.yml` runs application tests and a Linux amd64 compile on pull requests, pushes to `main`, and manual dispatch. It uses the same pinned Go Docker image and commands shown above, with a read-only repository token and no cPanel or ACME credentials.

The manually dispatched release workflow calls that same test workflow and waits for it to succeed before packaging and publishing. Its existing RPM/DEB build commands and asset names remain separate from the tests. For a new release, choose an unused `VERSION`/`ITERATION` combination before dispatch: a new tag targets the tested commit, but an existing tag is not moved. A green test job does not prove a package installs or that real ACME validation works. Static analysis remains a separate local check while the signal-channel finding above is unresolved.

## Integration and acceptance tests

Choose the smallest environment that exercises the changed boundary:

| Environment | Can verify | Does not verify |
| --- | --- | --- |
| Local Go tests with fake gateways/HTTP endpoints | Decisions, saved-state transitions and external call counts | Real cPanel installation or completed public ACME validation |
| Local ACME server such as Pebble | Full ACME protocol/challenge scenarios with controlled DNS and HTTP | Real cPanel, public DNS propagation or Let's Encrypt production rate limits |
| Dedicated cPanel dev VM with Let's Encrypt staging | Real account permissions, routing, DNS challenges, certificate installation and package lifecycle | Production fleet capacity or production rate-limit behavior |

There is currently no checked-in Pebble harness or staging shell runner. Test code can override the existing ACME URL variables and restore them afterward; the deployed plugin selects production/staging through its existing configuration. A local harness must also supply challenge responders, test CA trust and fake cPanel behavior. Do not disable challenge validation when the scenario is intended to test it.

If shell-based acceptance tests are added, put them under `tests/acceptance/` with a runner and documented prerequisites. Keep setup, named scenarios, assertions and cleanup distinct. Require an explicit disposable target/account, verify staging before issuing, bound DNS waits, fail on unexpected results, and clean up only fixtures owned by that run. Do not put automatic remote installation or customer-account discovery into the default local test command.

### cPanel dev-server workflow

1. Use a dedicated VM, snapshot it, and create a disposable account with a controlled public domain. Public HTTP-01 validation needs reachable challenge URLs; local hosts-file entries are insufficient. DNS-01 needs public authoritative TXT records the test can update.
2. Build and install the candidate on that VM. The renewal CLI talks to the daemon, so verify the daemon is running the candidate as well.
3. Create `/etc/letsencrypt-cpanel.use-staging` before starting/restarting the daemon. It selects staging at process startup and applies server-wide. Keep the VM on staging during the tests; staging certificates are not publicly trusted.
4. Establish a working certificate through the entry point being tested. Manual UI issuance, AutoSSL and renewal are separate paths; do not assume success in one proves the others.
5. Change one condition at a time, run the action, then inspect the installed certificate, persisted candidate/issued names and external calls. Recheck after a daemon restart when persistence matters.
6. Test both success and failure, repeated runs, recovery, primary versus optional names, HTTP versus DNS validation, wildcard overlap and missing reuse-target installations as applicable. For omitted-name recovery, verify ordinary checks leave a healthy certificate alone and the next actual renewal retries remembered names. A manual new issuance can add a recovered name sooner. A stable serial number alone does not prove installation was skipped; inspect API calls or logs too. Per-certificate renewal hooks and the loop-level hook are separate behaviors.
7. Repeat the relevant scenarios after an RPM upgrade. Restore the VM snapshot for rollback; restoring only the executable leaves changed account and certificate state behind.

Example renewal commands, run on the dev VM with `LABUSER` and `PUBLIC_TEST_DOMAIN` replaced:

```sh
# Staging issuance without installing the returned certificate or saving it in NVData.
le-cp ssl --user LABUSER renew --virtualhost PUBLIC_TEST_DOMAIN --dry-run

# Install/persist a replacement, bypassing the expiry gate.
# Run only after verifying the daemon is staging-configured.
le-cp ssl --user LABUSER renew --virtualhost PUBLIC_TEST_DOMAIN --force

# Exercise normal eligibility, reuse and recovery decisions.
le-cp ssl --user LABUSER renew --virtualhost PUBLIC_TEST_DOMAIN
```

Dry-run still contacts cPanel/ACME and creates temporary challenge files; DNS-01 can update TXT records. It is not an offline or side-effect-free test. It also bypasses normal renewal eligibility, so it cannot establish that ordinary repeated runs avoid issuance or reinstallation.

RPM verification is separate from compiling: `make rpm` uses Ruby/fpm, rpm tooling, gawk and dos2unix and builds both RPM and DEB. Review package installation hooks and use the disposable VM for installation tests.

## Reporting results

Record the exact revision, toolchain, commands, scenarios and observed results in the change's review notes. Separate test/build/vet results, fake-service evidence, real-server evidence and checks not performed. Keep this guide focused on reusable instructions rather than issue-specific run histories. Never include private keys, account tokens or raw NVData containing secrets in reports.

References: [Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/), [challenge types](https://letsencrypt.org/docs/challenge-types/), and [Pebble](https://github.com/letsencrypt/pebble).

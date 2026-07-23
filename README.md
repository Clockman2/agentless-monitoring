# Agentless Monitoring

A lightweight network discovery and monitoring platform for small and medium-sized infrastructure environments.

The project is being built incrementally. The current proof of concept provides authenticated machine monitoring, scheduled TCP/HTTP/HTTPS checks with thresholded history, bounded authorized IPv4 discovery across public or private networks, and reviewed import into groups.

## Run locally

Go 1.25 or newer is required.

```sh
go run ./cmd/agentless-monitoring -create-admin -username admin
go run ./cmd/agentless-monitoring
```

The server listens on `127.0.0.1:8080` by default. Verify it with:

```sh
curl http://127.0.0.1:8080/healthz
```

Use `-listen` to select a different address. Expose the service only through a properly configured reverse proxy or another trusted network boundary.

Runtime settings can also be supplied through environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGENTLESS_MONITORING_LISTEN_ADDRESS` | `127.0.0.1:8080` | HTTP bind address; use an explicit IP and port |
| `AGENTLESS_MONITORING_DATABASE_PATH` | `data/agentless-monitoring.db` | SQLite database file |
| `AGENTLESS_MONITORING_SECURE_COOKIES` | `false` | Require HTTPS and host-bound cookie names; mandatory for non-loopback listeners |
| `AGENTLESS_MONITORING_ALLOW_WEB_SETUP` | `false` | Temporarily permit first-user creation in the browser; local CLI bootstrap is preferred |
| `AGENTLESS_MONITORING_TRUSTED_PROXIES` | empty | Comma-separated proxy IPs or CIDRs allowed to supply `X-Forwarded-For` |
| `AGENTLESS_MONITORING_ALLOW_SENSITIVE_TARGETS` | `false` | Permit well-known cloud metadata and workload-credential endpoints |
| `AGENTLESS_MONITORING_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown deadline, up to five minutes |
| `AGENTLESS_MONITORING_WORKERS` | `4` | Concurrent scheduled-check workers, from 1 to 64 |
| `AGENTLESS_MONITORING_POLL_INTERVAL` | `2s` | How often the scheduler looks for due checks, from 500ms to one minute |

Command-line `-listen` and `-database` take precedence over their environment variables. The
`-create-admin -username NAME` mode reads and confirms the password without echoing it when
run from a terminal, creates the initial administrator, and exits.

## Development checks

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
```

GitHub Actions repeats these checks, scans changes for potential secrets, and runs CodeQL.
Dependabot groups weekly Go-module and workflow-action updates for review.

## Ubuntu installation

See [docs/ubuntu-install.md](docs/ubuntu-install.md) for the ordered fresh-install commands and reusable update script.

See [docs/poc.md](docs/poc.md) for the first end-to-end monitoring workflow and current POC boundaries.

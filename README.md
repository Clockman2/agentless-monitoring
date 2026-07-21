# Agentless Monitoring

A lightweight network discovery and monitoring platform for small and medium-sized infrastructure environments.

The project is being built incrementally. The current proof of concept provides authenticated machine monitoring, manual TCP/HTTP/HTTPS checks, bounded local IPv4 discovery, and reviewed import into groups.

## Run locally

Go 1.24 or newer is required.

```sh
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
| `AGENTLESS_MONITORING_SECURE_COOKIES` | `false` | Require HTTPS when browsers send authentication cookies |
| `AGENTLESS_MONITORING_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown deadline, up to five minutes |

Command-line `-listen` takes precedence over the listen-address environment variable.

## Development checks

```sh
go test ./...
go vet ./...
```

## Ubuntu installation

See [docs/ubuntu-install.md](docs/ubuntu-install.md) for the ordered fresh-install commands and reusable update script.

See [docs/poc.md](docs/poc.md) for the first end-to-end monitoring workflow and current POC boundaries.

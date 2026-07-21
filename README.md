# Agentless Monitoring

A lightweight network discovery and monitoring platform for small and medium-sized infrastructure environments.

The project is being built incrementally. The current foundation provides a small Go HTTP service with a health endpoint and graceful shutdown.

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

## Development checks

```sh
go test ./...
go vet ./...
```

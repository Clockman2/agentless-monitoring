# Ubuntu installation

The application currently installs from source. These commands support fresh 64-bit Ubuntu installations on amd64 and arm64.

Run each command in this exact order:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends ca-certificates curl git
sudo git clone --branch main --single-branch https://github.com/Clockman2/agentless-monitoring.git /opt/agentless-monitoring-src
sudo /opt/agentless-monitoring-src/scripts/install-ubuntu.sh
sudo systemctl status agentless-monitoring.service --no-pager
curl --fail http://127.0.0.1:8080/healthz
```

The installer:

- Installs the official Go toolchain after verifying its SHA-256 checksum.
- Builds and tests the application with CGO disabled.
- Creates the unprivileged `agentless-monitoring` system account.
- Stores application data in `/var/lib/agentless-monitoring`.
- Stores runtime settings in `/etc/default/agentless-monitoring`.
- Installs and starts a hardened systemd service.

The service listens only on `127.0.0.1:8080` by default. Use an SSH tunnel for remote testing:

```sh
ssh -L 8080:127.0.0.1:8080 ubuntu@SERVER_IP
```

Then open `http://127.0.0.1:8080/healthz` on the computer running the SSH command.

## Update

Run the reusable updater from the installed source checkout:

```sh
sudo /opt/agentless-monitoring-src/scripts/update-ubuntu.sh
```

The updater refreshes only the operating-system packages required by the application, fast-forwards the source checkout, verifies modules, runs tests, rebuilds the binary, installs updated service files, and restarts the service. It stops without changing the checkout when the source directory contains local modifications or is not on `main`.

The existing environment file and SQLite database are preserved during updates.

Existing installations use four monitoring workers and a two-second scheduler poll interval without requiring environment-file changes. To tune these values, add the following to `/etc/default/agentless-monitoring`, then restart the service:

```ini
AGENTLESS_MONITORING_WORKERS=4
AGENTLESS_MONITORING_POLL_INTERVAL=2s
```

```sh
sudo systemctl restart agentless-monitoring.service
```

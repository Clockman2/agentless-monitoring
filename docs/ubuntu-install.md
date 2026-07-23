# Ubuntu installation

The application currently installs from source. These commands support fresh 64-bit Ubuntu installations on amd64 and arm64.

Run each command in this exact order:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends ca-certificates curl git
sudo git clone --branch main --single-branch https://github.com/Clockman2/agentless-monitoring.git /opt/agentless-monitoring-src
COMMIT_SHA=REVIEWED_FULL_40_CHARACTER_COMMIT_SHA
sudo git -C /opt/agentless-monitoring-src checkout --detach "${COMMIT_SHA}"
sudo /opt/agentless-monitoring-src/scripts/install-ubuntu.sh
sudo -u agentless-monitoring /usr/local/bin/agentless-monitoring \
  -database /var/lib/agentless-monitoring/agentless-monitoring.db \
  -create-admin -username admin
sudo systemctl status agentless-monitoring.service --no-pager
curl --fail http://127.0.0.1:8080/healthz
```

The installer:

- Installs the official Go toolchain after verifying its SHA-256 checksum.
- Builds and tests the application with CGO disabled as a dedicated unprivileged build account
  that cannot access the runtime database.
- Creates the unprivileged `agentless-monitoring` system account.
- Stores application data in `/var/lib/agentless-monitoring`.
- Stores runtime settings in `/etc/default/agentless-monitoring`.
- Installs and starts a hardened systemd service.

The administrator command prompts for the password twice and does not place it in shell history
or the process argument list. Browser-based initial setup is disabled by default.

The service listens only on `127.0.0.1:8080` by default. Use an SSH tunnel for remote testing:

```sh
ssh -L 8080:127.0.0.1:8080 ubuntu@SERVER_IP
```

Then open `http://127.0.0.1:8080/healthz` on the computer running the SSH command.

## Update

Copy a reviewed full commit SHA from the expected GitHub repository, then run:

```sh
COMMIT_SHA=REVIEWED_FULL_40_CHARACTER_COMMIT_SHA
sudo /usr/local/sbin/agentless-monitoring-update --commit "${COMMIT_SHA}"
```

For an installation created before the pinned updater existed, install it once from the same
reviewed commit:

```sh
COMMIT_SHA=REVIEWED_FULL_40_CHARACTER_COMMIT_SHA
sudo git -C /opt/agentless-monitoring-src fetch --no-tags origin \
  main:refs/remotes/origin/main
sudo git -C /opt/agentless-monitoring-src checkout --detach "${COMMIT_SHA}"
sudo /opt/agentless-monitoring-src/scripts/install-ubuntu.sh --skip-packages
```

The updater refuses branch names and abbreviated SHAs. It verifies that the exact commit belongs
to `origin/main`, uses a temporary detached worktree, and runs module download, verification,
tests, and compilation as `agentless-monitoring-build`, which cannot access application state.
Root refreshes required Ubuntu packages,
installs only the built binary and next updater, then restarts the service. It refuses unexpected
repository remotes or a source checkout with local modifications.

The existing environment file and SQLite database are preserved during updates.

Existing installations use four monitoring workers and a two-second scheduler poll interval without requiring environment-file changes. To tune these values, add the following to `/etc/default/agentless-monitoring`, then restart the service:

```ini
AGENTLESS_MONITORING_WORKERS=4
AGENTLESS_MONITORING_POLL_INTERVAL=2s
```

```sh
sudo systemctl restart agentless-monitoring.service
```

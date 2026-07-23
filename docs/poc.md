# First POC workflow

The first proof of concept supports scheduled monitoring and reviewed local discovery:

1. Install or update the Ubuntu service.
2. Create the first administrator account.
3. Sign in to the operations console.
4. Add a machine with one TCP, HTTP, or HTTPS check.
5. Let the scheduler run the check or select **Run now**.
6. Review threshold state, response time, and result history.
7. Scan a private local IPv4 CIDR for responsive devices.
8. Select discovered devices and import them into a named group.

## Update an existing Ubuntu test installation

```sh
sudo /opt/agentless-monitoring-src/scripts/update-ubuntu.sh
```

For a fresh installation, create the initial administrator from the Ubuntu terminal:

```sh
sudo -u agentless-monitoring /usr/local/bin/agentless-monitoring \
  -database /var/lib/agentless-monitoring/agentless-monitoring.db \
  -create-admin -username admin
```

The command prompts twice for a unique password containing at least 12 characters. It does not
accept a password as a command-line argument.

The service listens on loopback by default. From another computer, create an SSH tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 ubuntu@SERVER_IP
```

Open `http://127.0.0.1:8080/` locally and sign in. No default credentials are created or stored
in the repository. Browser-based first-user setup is disabled by default.

## Add a monitored machine

Select **Machines** or **Add machine** from the dashboard, then enter:

- A display name.
- A literal private, loopback, or link-local IPv4 or IPv6 address.
- TCP, HTTP, or HTTPS as the check type.
- The destination port.
- An HTTP path when using HTTP or HTTPS.
- A check interval between 10 seconds and 24 hours.
- The consecutive failure and recovery thresholds.

Literal public and private unicast IP targets are supported. Hostnames remain intentionally unsupported in this POC. HTTP checks disable proxy use, restrict redirects to the same IP and scheme, and apply configured timeouts.

After adding the machine, the scheduler runs the check when it becomes due. **Run now** remains available for immediate diagnostics.

Every execution stores a raw history result with its timestamp, response time, error category, bounded summary, and worker name. Select **History** next to a dashboard check to view the latest 100 results.

A raw failure does not immediately mark a machine critical. The check becomes critical only after its configured number of consecutive failures. A configured number of consecutive successes returns it to healthy. The defaults are three failures and one success.

## Discover network devices and add them to a group

Open **Discovery** in the sidebar. The target may be:

- One public or private IPv4 address, such as `203.0.113.10`.
- An IPv4 CIDR from `/24` through `/32`, such as `203.0.113.0/24`.
- An inclusive IPv4 range containing at most 256 addresses, such as `203.0.113.10-203.0.113.40`.

Before starting each job, confirm that you own the target or have explicit authorization to scan it. Unspecified, multicast, IPv6, malformed, reversed, and oversized targets are rejected. Only one discovery job runs at a time.

The job runs in the background. Its page refreshes while it checks TCP ports 22, 80, 443, 445, 3389, and 8006. A successful connection or an explicit connection refusal identifies a responsive host. This avoids raw-socket and root requirements, but a host that silently drops every probe will not appear.

When the job completes:

1. Review the responsive IP addresses.
2. Select only the devices that should be monitored.
3. Enter a new or existing group name.
4. Select **Add selected to group**.

Discovery does not automatically monitor every response. The explicit review step prevents accidental inventory growth. During import, port 80 creates an HTTP check, port 443 creates an HTTPS check, and other detected ports create TCP checks. A reachable device with no open common port receives a TCP port 22 check as a conservative placeholder; it may remain critical until a suitable manual check is added.

To deploy this feature on the Ubuntu POC after pulling the new commits, run:

```sh
sudo /opt/agentless-monitoring-src/scripts/update-ubuntu.sh
```

The database migration and service restart are handled by the existing update workflow.

## Current POC boundaries

- There is one check per machine in the current form.
- Incidents, email notifications, editable checks, and maintenance mode are not implemented yet.
- Scheduling is process-local and uses a bounded worker pool; distributed workers are outside the POC.
- Discovery is IPv4-only, uses a fixed TCP probe set, and is limited to 256 addresses per job.
- HTTPS validates certificates normally; self-signed or mismatched certificates fail the check.
- Insecure cookies are accepted only with a loopback listener. Set `AGENTLESS_MONITORING_SECURE_COOKIES=true` when serving the application through HTTPS; this also enables browser-enforced `__Host-` cookie names.

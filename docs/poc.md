# First POC workflow

The first proof of concept supports a complete manual monitoring workflow:

1. Install or update the Ubuntu service.
2. Create the first administrator account.
3. Sign in to the operations console.
4. Add a machine with one TCP, HTTP, or HTTPS check.
5. Run the check manually.
6. Review the persisted status and response time on the dashboard.

## Update an existing Ubuntu test installation

```sh
sudo /opt/agentless-monitoring-src/scripts/update-ubuntu.sh
```

The service listens on loopback by default. From another computer, create an SSH tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 ubuntu@SERVER_IP
```

Open `http://127.0.0.1:8080/` locally. The first visit redirects to the administrator setup form.

Use a unique test password containing at least 12 characters. No default credentials are created or stored in the repository.

## Add a monitored machine

Select **Machines** or **Add machine** from the dashboard, then enter:

- A display name.
- A literal private, loopback, or link-local IPv4 or IPv6 address.
- TCP, HTTP, or HTTPS as the check type.
- The destination port.
- An HTTP path when using HTTP or HTTPS.

Public IP targets and hostnames are intentionally rejected in this POC. This prevents the monitoring server from becoming an unrestricted server-side request proxy while approved-network configuration is still under development.

After adding the machine, select **Run check**. The dashboard updates the machine to healthy or critical and records the response time or bounded error summary.

## Current POC boundaries

- Checks run manually; the scheduler is the next monitoring-engine milestone.
- There is one check per machine in the current form.
- Discovery, incidents, email notifications, groups, and maintenance mode are not implemented yet.
- HTTPS validates certificates normally; self-signed or mismatched certificates fail the check.
- Authentication cookies use the `Secure` flag only when `AGENTLESS_MONITORING_SECURE_COOKIES=true`. Enable it when serving the application through HTTPS.

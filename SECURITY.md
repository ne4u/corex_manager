# Security Policy

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately — do **not** open a
public GitHub issue.

- Use GitHub's [private vulnerability reporting](https://github.com/ne4u/corex_manager/security/advisories/new), or
- Email **akauffman@ne4u.com**

Include a description of the issue, steps to reproduce, and the affected
component (backend API, frontend, HAProxy config generation, WAF/Coraza
integration, MCP gateway, etc.). You will receive an acknowledgement as soon
as possible, and a fix or mitigation will be prioritized based on severity.

## Supported Versions

coreX Manager is under active development. Only the latest release on the
`main` branch receives security fixes.

## Production Hardening Checklist

The Docker Compose defaults are tuned for local development. Before exposing
a deployment to untrusted networks, make sure you:

- **Set a strong `SECRET_KEY`** (required; signs auth tokens). Generate one with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
- **Set `ADMIN_PASSWORD` before first boot.** If unset, a random admin password
  is generated and printed once in the API container logs.
- **Set `POSTGRES_PASSWORD`.** The compose file falls back to the weak default
  `haproxy` when unset.
- **Set `VALKEY_PASSWORD`.** Valkey runs without authentication when this is
  empty.
- **Set `CAP_ADMIN_KEY`** if the built-in Cap CAPTCHA service is enabled.
- **Set `MCP_SECRETS_KEY`** if you use the MCP gateway (encrypts stored
  upstream secrets).
- **Do not publish internal ports.** The API (`8000`), frontend (`3000`), and
  HAProxy stats (`8404`) should not be reachable from the public internet;
  front them with the managed HAProxy listeners or a trusted network.
- **Use TLS** for the management UI/API in production.
- **Keep `.env` out of version control** (it is gitignored) and restrict its
  file permissions on the host.

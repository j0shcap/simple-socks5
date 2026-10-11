# Security policy

## Supported versions

Only the latest 2.x minor release gets security fixes, as a new patch release. 2.0 gets no fixes, but its images
(`2.0.0`, `2.0`, `2.0.0-logging-disabled`) stay on Docker Hub for rollback.

## Reporting a vulnerability

Use GitHub's private reporting: the repo's **Security** tab → **Report a vulnerability**
(https://github.com/j0shcap/simple-socks5/security/advisories/new). Please don't open a public issue.
Include the version or image tag, your configuration and steps to reproduce.

## What to expect

You'll get a reply within a week. If the report is confirmed, the fix ships in a patch release with a GitHub
security advisory, and you're credited unless you'd rather not be.

## Out of scope

- Running without authentication, which makes an open proxy. This is documented, and the server warns about it
  at startup.
- Traffic, including credentials, crossing the network in cleartext. SOCKS5 has no encryption.

For deploying safely, see the README's [Security](README.md#security) section.

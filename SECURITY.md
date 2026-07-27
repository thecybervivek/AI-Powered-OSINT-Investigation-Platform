# Security Policy

## Supported version
The current main branch is the supported development version.

## Reporting a vulnerability
Do not open a public issue containing exploit details, credentials, API keys, personal data, or sensitive OSINT evidence. Report the issue privately to the project maintainer with reproduction steps and affected components.

## Operational requirements
Production deployments must use a unique secret key, HTTPS, PostgreSQL, Redis-backed rate limiting, explicit CORS origins and trusted hosts. API/provider credentials belong in environment variables or a secret manager and must never be committed to source control.

The platform is intended for lawful, authorized investigations. Operators are responsible for provider terms, privacy requirements, retention policies and applicable law.

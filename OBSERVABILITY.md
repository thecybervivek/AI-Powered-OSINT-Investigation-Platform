# Observability and Operations

## Probes

- `GET /health` is the liveness probe. It must not depend on external providers.
- `GET /ready` is the readiness probe and returns HTTP 503 when the database is unavailable.

## Request tracing

Every HTTP request is assigned a request ID by the request logging middleware. Preserve this value in centralized logs so API failures can be correlated across reverse proxies and application instances.

## Logging

Production logs should be shipped from stdout/stderr to the deployment platform's centralized logging system. Alert on sustained 5xx responses, authentication failures, rate-limit spikes, readiness failures, and repeated provider-integration errors.

Never log access tokens, passwords, provider API keys, raw authorization headers, or unnecessary personal data.

## Deployment gates

A release is eligible for deployment only after backend tests, frontend tests, frontend production build, and Docker image build succeed. The repository CI workflow enforces these gates on pushes and pull requests to `main`.

## Backup and recovery

Back up PostgreSQL independently from application containers. Test restoration periodically. Redis is treated as ephemeral infrastructure unless a deployment explicitly relies on persisted cache/rate-limit state. Application storage retention should follow the organization's evidence-retention policy.

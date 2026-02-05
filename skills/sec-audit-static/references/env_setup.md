# Environment Setup (Preferred)

When PoC or integration tests require services (DB/Elasticsearch/etc.), prefer Docker-based local environments.

Guidance:
- Use docker containers to provision required services.
- Keep test data minimal and isolated.
- If Docker is unavailable, fall back to non-integration PoC and mark manual verification.

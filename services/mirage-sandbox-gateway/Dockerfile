# mirage-sandbox-gateway (Step 9b: MirageEnvironmentController's WSS
# command channel + the sandbox-action HTTP API).
# See services/mirage-api/Dockerfile's header comment — same repo-root
# build-context / full-package-set rationale applies identically here.
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY contracts/python ./contracts/python
COPY libs ./libs
COPY services ./services
COPY agents ./agents
COPY canary ./canary
COPY scripts ./scripts

RUN pip install --no-cache-dir .
RUN groupadd --system mirage && useradd --system --gid mirage --home-dir /nonexistent --shell /usr/sbin/nologin mirage

ENV PYTHONUNBUFFERED=1

EXPOSE 8020

USER mirage

CMD ["python", "scripts/run-sandbox-gateway"]

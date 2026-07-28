# mirage-worker (Step 7's detection-into-cases adapter). No HTTP surface —
# a long-running NATS consumer loop, matches scripts/run-detection-adapter.
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

# Unbuffered stdout — otherwise `docker logs` shows nothing until Python's
# buffer fills, since a container's stdout is a pipe, not a TTY (the same
# buffering behavior the session's own debug scripts hit against
# redirected-to-file output, see ARCHITECTURE_DECISIONS.md).
ENV PYTHONUNBUFFERED=1

USER mirage

CMD ["python", "scripts/run-detection-adapter"]

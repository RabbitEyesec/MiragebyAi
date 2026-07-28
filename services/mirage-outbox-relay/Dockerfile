# mirage-outbox-relay (Step 6, §6.3's transactional outbox relay). No HTTP
# surface — a long-running polling loop, matches scripts/run-outbox-relay.
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

# Unbuffered stdout — see services/mirage-worker/Dockerfile's identical comment.
ENV PYTHONUNBUFFERED=1

USER mirage

CMD ["python", "scripts/run-outbox-relay"]

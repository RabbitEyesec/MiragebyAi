# mirage-api (Step 4b's engineering console + Step 8a's /route decision API).
# Build context is the repo root (see infra/compose/docker-compose.yml) —
# pyproject.toml's package-dir maps ALL ten mirage_* packages to their own
# directories ("one dependency set, one venv, many independently-named
# packages... deployment units stay separated by directory and by their own
# Dockerfile ENTRYPOINT"), so every package directory must be present for
# `pip install .` to succeed, even though this image only ever RUNS
# mirage_api's own code.
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

EXPOSE 8000

USER mirage

CMD ["python", "scripts/run-mirage-api"]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends file clamav yara \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY contracts ./contracts
COPY libs ./libs
COPY services ./services
COPY agents ./agents
COPY canary ./canary
COPY config/yara ./config/yara
RUN pip install --no-cache-dir . oletools

USER 65532:65532
CMD ["python", "-m", "mirage_artifact_scanner"]

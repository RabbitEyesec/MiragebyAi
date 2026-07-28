FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY contracts ./contracts
COPY libs ./libs
COPY services ./services
COPY agents ./agents
COPY canary ./canary
RUN pip install --no-cache-dir .
ENV PYTHONUNBUFFERED=1
USER 65532:65532
CMD ["python", "-m", "mirage_report_worker"]

# syntax=docker/dockerfile:1
# IOC Hunter's HTTP service, including the browser runtime for provider lookups.
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    IOC_HUNTER_STORE=/data \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
COPY pyproject.toml ./
COPY ioc_hunter ./ioc_hunter

# Bookworm provides the system libraries supported by Playwright's installer.
RUN pip install ".[extraction,browser,mcp,api]" \
    && playwright install --with-deps chromium \
    && chmod -R a+rx /ms-playwright

RUN useradd --create-home --uid 10001 ioc \
    && mkdir -p /data \
    && chown ioc:ioc /data

USER ioc
EXPOSE 8002

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8002/health', timeout=4)"]

CMD ["uvicorn", "ioc_hunter.http_api:app", "--host", "0.0.0.0", "--port", "8002"]

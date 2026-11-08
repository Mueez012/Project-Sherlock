# syntax=docker/dockerfile:1
# IOC Hunter's HTTP service, including the browser runtime for provider lookups.
#
# Layers go from rarely changed to often changed, so a code change rebuilds in seconds without downloading:
#   1. Python dependencies, from pyproject.toml only (uv, with a build cache that keeps finished downloads even
#      when a build fails halfway, plus a long timeout and retries for slow connections).
#   2. Chromium and its system libraries.
#   3. The code itself, installed without dependencies and without network.
FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    IOC_HUNTER_STORE=/data \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    UV_SYSTEM_PYTHON=1 \
    UV_LINK_MODE=copy \
    UV_HTTP_TIMEOUT=300 \
    UV_HTTP_RETRIES=10

WORKDIR /app

# 1. Dependencies only; re-runs only when pyproject.toml changes.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -r pyproject.toml --extra extraction --extra browser --extra mcp --extra api

# 2. Bookworm provides the system libraries supported by Playwright's installer.
RUN playwright install --with-deps chromium \
    && chmod -R a+rx /ms-playwright

# 3. The code; setuptools is already installed (spaCy needs it), so this needs no network.
COPY ioc_hunter ./ioc_hunter
RUN uv pip install --no-deps --no-build-isolation .

RUN useradd --create-home --uid 10001 ioc \
    && mkdir -p /data \
    && chown ioc:ioc /data

USER ioc
EXPOSE 8002

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8002/health', timeout=4)"]

CMD ["uvicorn", "ioc_hunter.http_api:app", "--host", "0.0.0.0", "--port", "8002"]

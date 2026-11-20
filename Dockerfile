# Build the wheel in one stage so pip and the toolchain stay out of the runtime.
FROM python:3.12-slim AS build
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --prefix=/install .

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/LeoAra03/netaudit" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="netaudit"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NETAUDIT_DB=/data/netaudit.db

RUN groupadd -r app && useradd -r -g app -d /app -s /usr/sbin/nologin app \
    && mkdir -p /data && chown app:app /data

COPY --from=build /install /usr/local

WORKDIR /app
USER app
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

# One worker on purpose: SQLite with several processes just adds write contention.
# See docs/adr/0002-sqlite-persistence.md
CMD ["uvicorn", "netaudit.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

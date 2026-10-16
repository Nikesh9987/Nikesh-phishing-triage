# Phishing Triage: multi-stage, non-root, small runtime image.
#   docker build -t phishing-triage:1.0.0 .
# Pin the base image by digest for reproducible production builds:
#   --build-arg PYTHON_VERSION=3.12   (3.11 or newer is required)

ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------- build stage
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Compilers are only needed if a dependency has no prebuilt wheel for this
# platform. This stage is discarded, so they never reach the final image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /build

# Dependencies first: this layer is reused until requirements.txt changes.
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Then the application itself (no dependency resolution, no editable install).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps . && pip check

# -------------------------------------------------------------- runtime stage
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="Phishing Triage" \
      org.opencontainers.image.description="Phishing triage and e-mail header parser: web dashboard, API and CLI" \
      org.opencontainers.image.version="1.0.0"

# Unprivileged user with no login shell and no home directory.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
               --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    HOME=/tmp \
    TMPDIR=/tmp \
    PHISHTRIAGE_API_HOST=0.0.0.0 \
    PHISHTRIAGE_API_PORT=8000

WORKDIR /app
USER 10001:10001

EXPOSE 8000

# Python is the only tool available in the image, so the check uses it.
# urlopen raises on any non-2xx answer, which makes the check fail.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request as u; u.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PHISHTRIAGE_API_PORT', '8000'), timeout=3)"]

# One worker, always: reports, rate limits and the intel cache live in memory.
CMD ["python", "-m", "phishtriage.api.app"]
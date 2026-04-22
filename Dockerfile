# syntax=docker/dockerfile:1.6

# ---- build stage --------------------------------------------------------
# Pin the base image by digest, not just by tag. Tag `3.11-slim` can be
# silently reassigned to a new build of Python 3.11 (e.g. to pick up a
# patched libc); pinning the sha256 makes the image supply-chain
# immutable — the bytes we're building against today are the bytes we'll
# keep building against until we explicitly bump this digest.
#
# To refresh: `docker buildx imagetools inspect python:3.11-slim` and
# copy the top-level `Digest:` value (the multi-arch index). Verify the
# image still builds with `docker build -t dmp-node:latest .` before
# landing the bump.
FROM python:3.11-slim@sha256:233de06753d30d120b1a3ce359d8d3be8bda78524cd8f520c99883bfe33964cf AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# zfec has a C extension; install a minimal build toolchain for the
# builder stage only. The runtime stage stays slim.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

# Copy only what pip needs so dependency layers cache cleanly.
COPY setup.py requirements.txt README.md ./
COPY dmp ./dmp

# Install into a dedicated prefix so we can copy it into the runtime image.
RUN pip install --prefix=/install --no-deps . \
 && pip install --prefix=/install \
        cryptography \
        dnspython \
        reedsolo \
        pyyaml \
        requests \
        argon2-cffi \
        zfec

# ---- runtime stage ------------------------------------------------------
# Same digest pin as the builder stage above; see the comment there for
# why this matters.
FROM python:3.11-slim@sha256:233de06753d30d120b1a3ce359d8d3be8bda78524cd8f520c99883bfe33964cf AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DMP_DB_PATH=/var/lib/dmp/dmp.db \
    DMP_DNS_HOST=0.0.0.0 \
    DMP_DNS_PORT=5353 \
    DMP_HTTP_HOST=0.0.0.0 \
    DMP_HTTP_PORT=8053

# curl is used by the HEALTHCHECK.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system dmp \
 && useradd --system --gid dmp --home-dir /var/lib/dmp --shell /usr/sbin/nologin dmp \
 && mkdir -p /var/lib/dmp \
 && chown -R dmp:dmp /var/lib/dmp

COPY --from=builder /install /usr/local

USER dmp
VOLUME ["/var/lib/dmp"]
EXPOSE 5353/udp 8053/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${DMP_HTTP_PORT}/health || exit 1

ENTRYPOINT ["python", "-m", "dmp.server"]

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
# image still builds with `docker build -t dnsmesh-node:latest .` before
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

# Copy only what pip needs so dependency layers cache cleanly. The
# hashed lockfile (generated via pip-compile --generate-hashes) comes
# first so its layer is reused across rebuilds that only touch source.
COPY requirements.lock requirements.txt setup.py README.md ./
COPY dmp ./dmp

# Install dependencies FIRST from the hashed lockfile with
# --require-hashes. This is the same dependency set CI's pip-audit
# gate verifies — so the published image is byte-identical (at the
# wheel-hash level) to what security review approved. A compromised
# PyPI mirror during a build cannot substitute different bytes
# without failing the hash check.
#
# Then install the package itself with --no-deps (deps are already
# resolved from the lockfile).
RUN pip install --prefix=/install --require-hashes -r requirements.lock \
 && pip install --prefix=/install --no-deps .

# ---- runtime stage ------------------------------------------------------
# Same digest pin as the builder stage above; see the comment there for
# why this matters.
FROM python:3.11-slim@sha256:233de06753d30d120b1a3ce359d8d3be8bda78524cd8f520c99883bfe33964cf AS runtime

# OCI image metadata. The publish-image workflow threads the git SHA
# and version tag through via --build-arg so each pushed image carries
# a back-reference to the commit it was built from. Docker Hub + GHCR
# render these fields on the image detail page.
ARG DMP_VERSION=dev
ARG DMP_REVISION=unknown
ARG DMP_CREATED=""
LABEL org.opencontainers.image.title="dnsmesh-node" \
      org.opencontainers.image.description="DNS Mesh Protocol node — federated end-to-end encrypted messaging over DNS." \
      org.opencontainers.image.source="https://github.com/oscarvalenzuelab/DNSMeshProtocol" \
      org.opencontainers.image.url="https://oscarvalenzuelab.github.io/DNSMeshProtocol/" \
      org.opencontainers.image.documentation="https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/docker" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.vendor="Oscar Valenzuela" \
      org.opencontainers.image.version="${DMP_VERSION}" \
      org.opencontainers.image.revision="${DMP_REVISION}" \
      org.opencontainers.image.created="${DMP_CREATED}"

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

FROM ubuntu:26.04

ARG GRYPE_VERSION=0.116.1
ARG TARGETARCH

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        jq \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
        amd64) grype_arch="amd64" ;; \
        arm64) grype_arch="arm64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --silent --show-error \
        "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${grype_arch}.tar.gz" \
        --output /tmp/grype.tar.gz; \
    tar --extract \
        --gzip \
        --file /tmp/grype.tar.gz \
        --directory /usr/local/bin \
        grype; \
    chmod 0755 /usr/local/bin/grype; \
    rm /tmp/grype.tar.gz; \
    grype version

RUN groupadd --gid 10001 scanner \
    && useradd \
        --uid 10001 \
        --gid scanner \
        --create-home \
        --shell /bin/bash \
        scanner \
    && mkdir -p /config /home/scanner/.cache/grype \
    && chown -R scanner:scanner /config /home/scanner

COPY --chmod=0755 scan-images.sh /usr/local/bin/scan-images.sh

USER scanner

ENV HOME=/home/scanner
ENV GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype/db

ENTRYPOINT ["/usr/local/bin/scan-images.sh"]
CMD ["/config/images.json", "/var/run/secrets/kubernetes.io/serviceaccount/token"]
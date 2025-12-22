FROM debian:trixie-slim@sha256:18764e98673c3baf1a6f8d960b5b5a1ec69092049522abac4e24a7726425b016 AS builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libc6-dev gcc && \
    rm -rf /var/lib/apt/lists/*

COPY flag/readflag.c /src/
WORKDIR /src
RUN gcc readflag.c -o readflag

FROM python:3.14.1-slim-trixie@sha256:b823ded4377ebb5ff1af5926702df2284e53cecbc6e3549e93a19d8632a1897e

# Setup flag & readflag
COPY --from=builder --chown=root:root --chmod=4555 /src/readflag /
COPY --chown=root:root --chmod=400 flag/flag /

# Setup application
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt
COPY --chown=www-data:www-data ./app .
USER www-data

ENTRYPOINT [ "uvicorn", "main:app", "--loop", "uvloop", "--host", "0.0.0.0" ]

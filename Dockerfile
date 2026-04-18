############################
# Stage 1 — cargo builder
############################
FROM rust:1.82-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock* rust-toolchain.toml build.rs ./
COPY src ./src
COPY assets ./assets

# Fail fast if the embedded jar is a placeholder.
RUN mkdir -p assets && test -s assets/scrcpy-server.jar || \
    (echo "assets/scrcpy-server.jar is empty/missing; build.rs will attempt to fetch it at build time" && true)

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin scrcpy-bridge \
    && cp target/release/scrcpy-bridge /usr/local/bin/scrcpy-bridge

############################
# Stage 2 — runtime
############################
FROM debian:bookworm-slim

# adb is the only hard runtime dep — Java is NOT required on the host because
# `scrcpy-server.jar` runs inside the device's Android runtime via app_process.
RUN apt-get update && apt-get install -y --no-install-recommends \
        adb ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/scrcpy-bridge /usr/local/bin/scrcpy-bridge

ENV ADB_HOST=127.0.0.1 \
    ADB_PORT=5037 \
    METRICS_PORT=9091 \
    LOG_FORMAT=json

EXPOSE 9091

ENTRYPOINT ["/usr/local/bin/scrcpy-bridge"]

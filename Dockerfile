# AppCrane production image for HaiveHub — the reverse-tunnel hub.
# Stage 1 builds the hub from source; stage 2 is a slim runtime that also carries
# the agent binaries the hub serves at /bin/* (one-line install + auto-update).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# Only the hub crate (and its deps) — no xcap/nokhwa/PTY, so no extra apt deps.
RUN cargo build --release -p haive-hub

FROM debian:bookworm-slim AS run
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/HaiveHub /app/HaiveHub
# Agent binaries served at /bin/* — pulled from the latest GitHub release so the
# image always ships current agents (install command + auto-update both use these).
RUN mkdir -p /app/dist \
 && for a in HaiveControl-linux HaiveControl-macos HaiveControl-windows.exe; do \
      curl -fsSL "https://github.com/gitayg/HaiveControl/releases/latest/download/$a" -o "/app/dist/$a"; \
    done
ENV HUB_DIST=/app/dist
COPY deployhub.json ./
# Must match deployhub.json "port"; the hub binds $PORT (AppCrane injects it).
EXPOSE 8770
# AppCrane requires a non-root runtime user.
RUN useradd -m -u 1000 hive && chown -R hive:hive /app
USER hive
CMD ["/app/HaiveHub"]

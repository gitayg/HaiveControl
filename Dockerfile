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
 && for a in HaiveControl-linux HaiveControl-linux-arm64 HaiveControl-macos HaiveControl-windows.exe \
             haive-mcp-linux haive-mcp-macos haive-mcp-windows.exe; do \
      curl -fsSL "https://github.com/gitayg/HaiveControl/releases/latest/download/$a" -o "/app/dist/$a"; \
    done
# Leaflet for the device map's real basemap (served at /bin/leaflet.*). Non-fatal:
# if the fetch fails the map falls back to the offline graticule.
RUN curl -fsSL "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" -o /app/dist/leaflet.js \
 && curl -fsSL "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" -o /app/dist/leaflet.css \
 || echo "leaflet download skipped — map will use the graticule fallback"
ENV HUB_DIST=/app/dist
# Persistent, writable data dir (custom scripts, schedules, recordings, plugins).
# Point at the AppCrane persistent volume so it survives redeploys.
ENV HUB_DATA=/data
COPY deployhub.json ./
# Must match deployhub.json "port"; the hub binds $PORT (AppCrane injects it).
EXPOSE 8770
# AppCrane requires a non-root runtime user.
RUN useradd -m -u 1000 hive && mkdir -p /data && chown -R hive:hive /app /data
USER hive
CMD ["/app/HaiveHub"]

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
# Agent binaries served at /bin/* — pulled from the PUBLIC haive-agent release (an
# anonymous download; no token needed) so the image always ships current agents
# (install command + auto-update both use these).
#
# AGENT_REV exists ONLY to bust this layer's Docker cache. The RUN below fetches
# `releases/latest`, but its cache key doesn't change when a new agent is released
# — so redeploying the hub would silently keep serving the OLD binaries (it only
# refreshed by luck, when a hub-source change happened to invalidate the layer).
# Bump this to the agent version you want picked up whenever you cut an agent release.
ARG AGENT_REV=2.28.2
RUN echo "agent rev: $AGENT_REV" \
 && mkdir -p /app/dist \
 && for a in HaiveControl-linux HaiveControl-linux-arm64 HaiveControl-macos HaiveControl-windows.exe \
             haive-mcp-linux haive-mcp-linux-arm64 haive-mcp-macos haive-mcp-windows.exe; do \
      curl -fsSL "https://github.com/gitayg/haive-agent/releases/latest/download/$a" -o "/app/dist/$a"; \
    done
# Published checksums, served at /bin/SHA256SUMS, so the 'crane' install source can
# verify integrity too. Non-fatal if a release predates checksums.
RUN curl -fsSL "https://github.com/gitayg/haive-agent/releases/latest/download/SHA256SUMS" \
      -o /app/dist/SHA256SUMS || echo "no SHA256SUMS in latest release yet"
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

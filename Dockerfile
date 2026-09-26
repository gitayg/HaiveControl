# AppCrane production image for it-ai-hub — the reverse-tunnel hub.
# Stage 1 builds the hub from source; stage 2 is a slim runtime that also carries
# the agent binaries the hub serves at /bin/* (one-line install + auto-update).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# Only the hub crate (and its deps) — no xcap/nokhwa/PTY, so no extra apt deps.
RUN cargo build --release -p it-ai-hub

FROM debian:bookworm-slim AS run
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/it-ai-hub /app/it-ai-hub
# Agent binaries served at /bin/* — pulled from the PUBLIC haive-agent release (an
# anonymous download; no token needed) so the image always ships current agents
# (install command + auto-update both use these).
#
# AGENT_REV PINS the agent release served at /bin — every URL below is
# releases/download/v${AGENT_REV}, never `latest`. It used to fetch `latest` and
# use AGENT_REV only as a cache-buster, so the version served was whatever was
# newest at build time, not what AGENT_VERSION (below) says is served. That match
# is load-bearing: hub auto-update pushes any agent whose version differs from
# AGENT_VERSION, so if the served binary were a different version, every agent
# would install it, report that version, and be pushed again — forever. Pinning
# makes the two the same number by construction, and a bad AGENT_REV fails the
# BUILD (curl -f + exit 1) instead of shipping a hub that serves the wrong agent.
ARG AGENT_REV=3.5.2
RUN echo "agent rev: $AGENT_REV" \
 && mkdir -p /app/dist \
 && for a in it-ai-linux it-ai-linux-arm64 it-ai-macos it-ai-windows.exe \
             it-ai-linux.deb it-ai-linux-arm64.deb \
             it-ai-mcp-linux it-ai-mcp-linux-arm64 it-ai-mcp-macos it-ai-mcp-windows.exe; do \
      curl -fsSL "https://github.com/gitayg/haive-agent/releases/download/v${AGENT_REV}/$a" -o "/app/dist/$a" || exit 1; \
      curl -fsSL "https://github.com/gitayg/haive-agent/releases/download/v${AGENT_REV}/$a.sig" -o "/app/dist/$a.sig" \
        || echo "no signature for $a yet (agents ≥3.0.7 require it for verified self-update)"; \
    done
# Published checksums, served at /bin/SHA256SUMS, so the 'crane' install source can
# verify integrity too. Non-fatal if a release predates checksums.
RUN curl -fsSL "https://github.com/gitayg/haive-agent/releases/download/v${AGENT_REV}/SHA256SUMS" \
      -o /app/dist/SHA256SUMS || echo "no SHA256SUMS in v${AGENT_REV}"
# Leaflet for the device map's real basemap (served at /bin/leaflet.*). Non-fatal:
# if the fetch fails the map falls back to the offline graticule.
RUN curl -fsSL "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" -o /app/dist/leaflet.js \
 && curl -fsSL "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" -o /app/dist/leaflet.css \
 || echo "leaflet download skipped — map will use the graticule fallback"
ENV HUB_DIST=/app/dist
# The dashboard's "latest agent" label + Update button read AGENT_VERSION. Derive
# it from AGENT_REV so ONE bump keeps the served binary and the label in sync —
# the two used to be separate (an AGENT_VERSION AppCrane secret) and drifted apart
# (label stuck at an old version while /bin served a newer one). NOTE: an
# AGENT_VERSION *secret*, if set, overrides this at runtime — remove that secret
# so this build-time value (from AGENT_REV) becomes the single source of truth.
ENV AGENT_VERSION=${AGENT_REV}
# Persistent, writable data dir (custom scripts, schedules, recordings, plugins).
# Point at the AppCrane persistent volume so it survives redeploys.
ENV HUB_DATA=/data
COPY deployhub.json ./
# Must match deployhub.json "port"; the hub binds $PORT (AppCrane injects it).
EXPOSE 8770
# AppCrane requires a non-root runtime user.
RUN useradd -m -u 1000 hive && mkdir -p /data && chown -R hive:hive /app /data
USER hive
LABEL org.opencontainers.image.licenses="Elastic-2.0"
CMD ["/app/it-ai-hub"]

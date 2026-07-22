# node:24-alpine (Node 24 LTS is the deployment target), pinned by digest so the
# base cannot float on a mutable tag. Refresh the digest deliberately when
# bumping Node. Resolve a new one with:
#   docker manifest inspect node:24-alpine
# (History: this pin was briefly removed on the theory that it broke Railway
# builds. It didn't — the breaker was a VOLUME instruction, since removed, and
# Railway's green 2026-07-22 build pulled this exact digest. Safe to keep pinned.)
FROM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd
WORKDIR /app
# Copy with node ownership so the unprivileged runtime user can read the files.
# server.js is the composition root; lib/ holds the modules it requires; public/
# is the static frontend (index.html + css/ + js/ ES modules). No node_modules:
# the app has zero runtime dependencies, and the one devDependency (Playwright)
# is never installed here, so it never ships in the image.
COPY --chown=node:node package.json ./
COPY --chown=node:node server.js ./
COPY --chown=node:node lib/ ./lib/
COPY --chown=node:node public/ ./public/
# The durable audit store (PD_DATA_DIR, default /app/data) must be writable by
# the unprivileged runtime user. Create it node-owned so the default works and
# so a named volume mounted here inherits node ownership on first initialization.
# Mount a volume at /app/data to persist records across container replacement
# (see the README "Records and retention" section).
#
# Deliberately NO `VOLUME /app/data` instruction here: Railway's builder does not
# support the VOLUME instruction and fails the whole build opaquely (~3s into
# BUILD_IMAGE with zero output — every deploy from the commit that introduced it
# until the commit that removed it failed this way). VOLUME only declared an
# anonymous-volume mount point; explicit mounts (`docker run -v pd-data:/app/data`,
# compose volumes, Railway's own volume feature) work identically without it, and
# the mkdir/chown below is what actually provides the writable, node-owned dir.
# Create it 0700, not the default 0755: the store holds client PII and the exact
# documents mailed, so it must not be group or other readable. lib/store.js
# ensureDataDir re-enforces 0700 at startup in case a mounted volume arrives
# with a looser mode.
RUN mkdir -p -m 0700 /app/data && chown node:node /app/data
EXPOSE 3491
ENV PORT=3491
ENV NODE_ENV=production
# Drop root: run as the built-in unprivileged "node" user.
USER node
# Alpine ships busybox wget (no curl) — use it to probe the login page.
# Shell-form CMD so ${PORT} expands: the server binds $PORT, so a probe hardcoded
# to 3491 would fail (and loop-restart the container) under any port override.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null "http://localhost:${PORT}/login" || exit 1
CMD ["node", "server.js"]

# node:24-alpine (Node 24 LTS is the deployment target), pinned by digest so the
# base cannot float on a mutable tag. Refresh the digest deliberately when
# bumping Node. Resolve a new one with:
#   docker manifest inspect node:24-alpine
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
RUN mkdir -p /app/data && chown node:node /app/data
VOLUME /app/data
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

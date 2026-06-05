FROM node:20-alpine
WORKDIR /app
# Copy with node ownership so the unprivileged runtime user can read the files.
COPY --chown=node:node package.json ./
COPY --chown=node:node server.js ./
COPY --chown=node:node public/ ./public/
EXPOSE 3491
ENV PORT=3491
ENV NODE_ENV=production
# Drop root: run as the built-in unprivileged "node" user.
USER node
# Alpine ships busybox wget (no curl) — use it to probe the login page.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:3491/login || exit 1
CMD ["node", "server.js"]

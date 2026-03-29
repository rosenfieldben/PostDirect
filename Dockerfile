FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY server.js ./
RUN mkdir -p public
COPY index.html ./public/
EXPOSE 3491
ENV PORT=3491
CMD ["node", "server.js"]

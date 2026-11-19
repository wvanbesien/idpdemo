FROM node:22-alpine
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY . .
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null 2>&1 || (wget -qO- --no-check-certificate https://127.0.0.1:${PORT}/healthz >/dev/null 2>&1) || exit 1
CMD ["node", "server.js"]

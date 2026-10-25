# syntax=docker/dockerfile:1

FROM node:22-bookworm AS build
WORKDIR /app

# Native deps for better-sqlite3 (and similar)
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --legacy-peer-deps

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3001

COPY package*.json ./
RUN npm ci --omit=dev --legacy-peer-deps

COPY --from=build /app/dist ./dist

# Only /app/data needs to be writable; dist/ stays root-owned (read-only).
RUN mkdir -p /app/data && chown node:node /app/data
USER node

EXPOSE 3001
CMD ["node", "dist/index.js"]

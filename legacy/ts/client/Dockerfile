# syntax=docker/dockerfile:1

# ── Stage 1: Install dependencies ──
FROM node:22-bookworm AS deps
WORKDIR /app

COPY package*.json ./
RUN npm ci --legacy-peer-deps

# ── Stage 2: Build the Next.js app ──
FROM node:22-bookworm AS build
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_API_URL=http://localhost:3001/api
ARG NEXT_PUBLIC_WS_URL=ws://localhost:3001/ws

ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL
ENV NEXT_TELEMETRY_DISABLED=1
# Produce the standalone server output the runtime stage copies (.next/standalone).
# next.config.ts only emits it when STANDALONE=1. SEC-20260621-015.
ENV STANDALONE=1

RUN npm run build

# ── Stage 3: Production runtime ──
FROM node:22-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Copy standalone output (includes server + minimal node_modules)
COPY --from=build /app/.next/standalone ./
# Copy static assets and public folder
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public

USER node

EXPOSE 3000

CMD ["node", "server.js"]

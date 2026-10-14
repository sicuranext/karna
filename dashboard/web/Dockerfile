# syntax=docker/dockerfile:1
# Karna dashboard web — hardened static frontend.
# Two stages: vendored Node build → minimal non-root nginx serving static files.
# Base images are pinned by digest (refresh digests when bumping the tag).

# ---- build stage ----
FROM node:22-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752 AS build
WORKDIR /app
# Install with the lockfile only first for cache-friendly, reproducible installs.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# Container build talks to the FastAPI backend; pass --build-arg
# VITE_DATA_MODE=sample for a self-contained sample build.
ARG VITE_DATA_MODE=live
RUN VITE_DATA_MODE=$VITE_DATA_MODE npm run build

# ---- runtime stage ----
# nginx-unprivileged runs as uid 101 (non-root) and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:56b8272e43a0525f67aed68d1e0794a712d10e3e45a563e118e9a77c817e6f86
# Static bundle only — no source, no node, no build tools in the runtime image.
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
EXPOSE 8080

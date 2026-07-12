# Cerberus v2 — frontend dashboard
#
# Multi-stage: build the static Vite bundle with Node, then serve it
# with a lightweight static server (no Node needed at runtime, much
# smaller final image).
#
# IMPORTANT Vite quirk: VITE_* env vars are baked into the built JS
# bundle at BUILD time, not read at container runtime like a typical
# server-side env var. That's why these are passed as build ARGs
# (from docker-compose.yml's `args:`) rather than a runtime `environment:`
# block — a runtime env var would have zero effect on an already-built
# static bundle.
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .

# Capture the build args sent from docker-compose
ARG VITE_API_BASE_URL
ARG VITE_API_KEY

# Assign them to environment variables so the Vite build process sees them
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_API_KEY=${VITE_API_KEY}

RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
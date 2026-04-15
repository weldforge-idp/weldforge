# ============================================================
# Multi-stage build: Node 20 compile → nginx:alpine runtime.
# Non-root nginx, security headers, health check.
# ============================================================

# --- Build stage ---
FROM node:20-alpine AS build
WORKDIR /app

# Cache dependencies before copying source
COPY package*.json ./
RUN npm ci --legacy-peer-deps

# Copy source and build
COPY . .
RUN npx ng build --configuration production

# --- Runtime stage ---
FROM nginx:alpine

# Strip the stock default server block. The real nginx config is
# provided at runtime by the `frontend-nginx-config` ConfigMap,
# mounted at /etc/nginx/templates and processed by the nginx:alpine
# entrypoint via envsubst (to inject the APP_API_KEY secret).
# See SECURITY_AUDIT_2026-04-15.md HIGH-1 for background.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY --from=build /app/dist/intelli-sso-admin-portal/browser /usr/share/nginx/html

# Security: ensure files are readable but not writable by nginx worker
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chmod -R 555 /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:80/ || exit 1

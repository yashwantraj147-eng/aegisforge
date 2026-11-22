# ==============================================================================
# AegisForge Frontend Dockerfile (Multi-Stage Production Build)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build static assets with Node.js & Vite
# ------------------------------------------------------------------------------
FROM node:20-alpine AS build

WORKDIR /app

# Copy dependency manifests for caching
COPY package*.json ./
RUN npm install --frozen-lockfile || npm install

# Copy source code and build production distribution
COPY . .
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Serve with Hardened Nginx
# ------------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# Copy compiled SPA bundle to Nginx document root
COPY --from=build /app/dist /usr/share/nginx/html

# Copy production Nginx reverse proxy configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# Healthcheck testing HTTP response
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:80/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]

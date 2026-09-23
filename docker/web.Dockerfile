# Frontend Web Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY apps/web/package*.json ./
COPY packages/shared-types/package*.json ../packages/shared-types/

# Install dependencies
RUN npm ci

# Copy source
COPY apps/web ./apps/web
COPY packages/shared-types ./packages/shared-types

# Build
WORKDIR /app/apps/web
RUN npm run build

# Runtime stage - serve with nginx
FROM nginx:alpine

COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
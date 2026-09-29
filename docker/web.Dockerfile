# Frontend Web Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app/apps/web

# Copy package files
COPY apps/web/package*.json ./

# Install dependencies
RUN npm ci

# Copy web source files
COPY apps/web ./

# Build frontend
RUN npm run build

# Runtime stage - serve with nginx
FROM nginx:alpine

COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
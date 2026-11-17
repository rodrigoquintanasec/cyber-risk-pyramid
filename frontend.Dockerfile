# Cyber Risk Pyramid - web UI: build with Node, serve static files with unprivileged nginx (which also proxies /api to the backend).
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.ts tsconfig.json postcss.config.js tailwind.config.js ./
COPY src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=5 CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

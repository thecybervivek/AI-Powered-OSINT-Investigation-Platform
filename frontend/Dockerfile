FROM node:22-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build


FROM nginx:1.27-alpine

# Prepare nginx for execution as the existing unprivileged nginx user.
RUN mkdir -p \
        /var/cache/nginx/client_temp \
        /var/cache/nginx/proxy_temp \
        /var/cache/nginx/fastcgi_temp \
        /var/cache/nginx/uwsgi_temp \
        /var/cache/nginx/scgi_temp \
        /tmp/nginx \
    && chown -R nginx:nginx \
        /var/cache/nginx \
        /tmp/nginx \
        /usr/share/nginx/html \
        /etc/nginx/conf.d \
    && sed -i 's#pid[[:space:]]\+/run/nginx.pid;#pid /tmp/nginx/nginx.pid;#' \
        /etc/nginx/nginx.conf

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

RUN chown -R nginx:nginx \
    /usr/share/nginx/html \
    /etc/nginx/conf.d

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:8080/ >/dev/null || exit 1
# Build stage
ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginx:alpine
FROM ${NODE_IMAGE} AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Serve stage
FROM ${NGINX_IMAGE}

COPY --from=build /app/dist /usr/share/nginx/html

RUN printf 'server { listen 80; root /usr/share/nginx/html; location / { try_files $uri $uri/ /index.html; } }\n' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

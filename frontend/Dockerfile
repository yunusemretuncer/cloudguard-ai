# ============================================================================
# Stage 1: Build
# Vite ile statik production build üret. Tüm dev paketleri bu stage'de kalır,
# final image'a sızmaz.
# ============================================================================
FROM node:20-alpine AS build

WORKDIR /app

# Önce package*.json kopyala — npm ci layer'ını cache'lemek için
COPY package*.json ./
RUN npm ci

# Kaynak kodu kopyala ve build et
COPY . .
RUN npm run build

# ============================================================================
# Stage 2: Serve
# nginx ile statik dosyaları sun. Production-grade, küçük image (~25MB).
# ============================================================================
FROM nginx:alpine

# Vite build çıktısı /app/dist'e gider, nginx'in default klasörüne kopyala
COPY --from=build /app/dist /usr/share/nginx/html

# SPA routing için custom nginx config (React Router falan kullanırsak)
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
#!/bin/bash

# V8Box Auto-Installer for Ubuntu/Debian
set -e

echo "🚀 Memulai Instalasi V8Box..."

# 1. Update & Install Dependensi Dasar
sudo apt-get update
sudo apt-get install -y curl git zip unzip tar

# 2. Install nerdctl & containerd (jika belum ada)
if ! command -v nerdctl &> /dev/null; then
    echo "📦 Memasang nerdctl & containerd..."
    curl -L https://github.com/containerd/nerdctl/releases/download/v1.7.2/nerdctl-full-1.7.2-linux-amd64.tar.gz -o nerdctl.tar.gz
    sudo tar Cxzf /usr/local  nerdctl.tar.gz
    rm nerdctl.tar.gz
    sudo systemctl enable --now containerd
fi

# 3. Persiapan Folder Proyek
mkdir -p v8box/functions v8box/storage/s3 v8box/storage/libsql v8box/data/caddy
cd v8box

# 4. Input Konfigurasi dari User
read -p "Masukkan Domain Utama (ex: apapun.tld): " DOMAIN
read -p "Masukkan Cloudflare API Token: " CF_TOKEN
read -sp "Masukkan Password Admin Dashboard: " ADMIN_PASS
echo ""

# 5. Membuat File .env
cat <<EOF > .env
DOMAIN=$DOMAIN
CLOUDFLARE_TOKEN=$CF_TOKEN
ADMIN_PASSWORD=$ADMIN_PASS
EOF

# 6. Membuat Caddyfile
cat <<EOF > Caddyfile
*.$DOMAIN, $DOMAIN {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy v8box:8080
}
EOF

# 7. Membuat compose.yaml
cat <<EOF > compose.yaml
services:
  caddy:
    image: caddy:2-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - ./data/caddy:/data
    environment:
      - CF_API_TOKEN=\${CLOUDFLARE_TOKEN}
    restart: always

  v8box:
    image: denoland/deno:alpine
    working_dir: /app
    volumes:
      - .:/app
    environment:
      - ADMIN_PASSWORD=\${ADMIN_PASSWORD}
      - DOMAIN=\${DOMAIN}
    command: run --allow-all server.ts
    restart: always

  s3:
    image: chrislusf/seaweedfs
    command: "server -dir=/data -s3 -filer"
    volumes:
      - ./storage/s3:/data
    restart: always

  cache:
    image: valkey/valkey:latest
    restart: always
EOF

# 8. Membuat template server.ts sederhana untuk inisialisasi
cat <<EOF > server.ts
import { Hono } from "https://deno.land/x/hono/mod.ts";
const app = new Hono();

app.get("/", (c) => c.text("V8Box is Running!"));
app.get("/dashboard", (c) => c.html("<h1>V8Box Dashboard</h1><p>Gunakan password dari .env untuk login.</p>"));

Deno.serve({ port: 8080 }, app.fetch);
EOF

# 9. Menjalankan Stack dengan Nerdctl
echo "🏗️ Menjalankan kontainer..."
sudo nerdctl compose up -d

echo "✅ Instalasi Selesai!"
echo "Dashboard: https://admin.$DOMAIN"
echo "Folder Kerja: $(pwd)"

# V8Box Deployment Guide

## 🎯 Deployment Modes

V8Box mendukung **dua mode deployment** yang berbeda:

| Mode | Use Case | Components | SSL | Subdomain |
|------|----------|------------|-----|-----------|
| **Development** | Local testing | Manual Deno + Infrastructure | ❌ | Optional |
| **Production** | VPS deployment | Full Docker Stack + Caddy | ✅ | ✅ |

---

## 🔧 Mode 1: Development (Local Testing)

### Prerequisites

- ✅ Deno installed
- ✅ Docker Desktop running

### Setup Steps

#### 1. Start Infrastructure Only

```bash
cd v8box

# Start infrastructure services (tanpa Caddy & V8Box server)
docker-compose up -d libsql valkey seaweedfs
```

#### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```env
DOMAIN=localhost
ADMIN_PASSWORD=dev-password
# Service URLs otomatis handled oleh server.ts defaults
```

#### 3. S3 Bucket Initialization

Bucket default akan dibuat otomatis saat server start (`S3_DEFAULT_BUCKET`, `S3_PROJECTS_BUCKET`, `S3_FUNCTIONS_BUCKET`).

#### 4. Run Server Manually

```bash
# Development mode (auto-reload)
deno task dev
```

#### 5. Access Points

- **Direct access** (recommended untuk `DOMAIN=localhost`):
  - Admin: `http://localhost:8000/admin`
  - API: `http://localhost:8000/run/hello`
  - Pages: `http://localhost:8000/pages/test`

- **Dengan subdomain** (opsional, perlu edit hosts):
  - `http://admin.localhost:8000`
  - `http://api.localhost:8000/run/hello`
  - `http://test.localhost:8000` (untuk pages)

#### Edit Hosts File (Optional)

**Windows:** `C:\Windows\System32\drivers\etc\hosts`

Add:
```
127.0.0.1  admin.localhost
127.0.0.1  api.localhost
127.0.0.1  test.localhost
```

### Development Workflow

```bash
# Edit worker
code functions/hello.ts

# Server auto-reload (dengan deno task dev)
# Test immediately
curl http://localhost:8000/run/hello

# View logs
tail -f logs/hello.log
```

---

## 🚀 Mode 2: Production (Full Stack - VPS Deployment)

### Prerequisites

- ✅ Ubuntu/Debian VPS
- ✅ Domain dengan wildcard DNS
- ✅ Cloudflare account (untuk auto SSL)

### Auto Install (One-Liner)

```bash
curl -sSL https://raw.githubusercontent.com/ardantus/v8box/main/install.sh | bash
```

Script ini akan:
1. Install nerdctl & containerd
2. Download V8Box
3. Konfigurasi domain & Cloudflare
4. Setup .env
5. Generate Caddyfile
6. Start full stack

### Manual Setup

#### 1. Clone Repository

```bash
git clone https://github.com/ardantus/v8box.git
cd v8box
```

#### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

Production `.env`:
```env
DOMAIN=yourdomain.com
CLOUDFLARE_TOKEN=your-cloudflare-api-token
ADMIN_PASSWORD=strong-production-password
S3_ACCESS_KEY=admin
S3_SECRET_KEY=strong-secret-here
S3_DEFAULT_BUCKET=v8box
S3_PROJECTS_BUCKET=v8box-projects
S3_FUNCTIONS_BUCKET=v8box-functions
```

#### 3. Configure DNS

Di Cloudflare DNS, tambahkan record:

```
Type    Name    Content          Proxy Status
A       @       YOUR_VPS_IP      DNS only (gray cloud)
A       *       YOUR_VPS_IP      DNS only (gray cloud)
```

> [!WARNING]
> **Matikan Cloudflare Proxy (gray cloud)** untuk Caddy DNS challenge bekerja dengan baik.

#### 4. Get Cloudflare API Token

1. Login to Cloudflare Dashboard
2. My Profile → API Tokens → Create Token
3. Template: **Edit zone DNS**
4. Permissions:
   - Zone → DNS → Edit
   - Zone → Zone → Read
5. Zone Resources: Include → Specific zone → `yourdomain.com`
6. Create Token → Copy token

#### 5. Update Caddyfile

Edit `Caddyfile`:
```caddyfile
*.{$DOMAIN}, {$DOMAIN} {
    tls {
        dns cloudflare {$CF_API_TOKEN}
    }

    reverse_proxy v8box:8000 {
        header_up Host {host}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }

    encode gzip
    
    log {
        output file /data/access.log
    }
}
```

#### 6. Start Full Stack

```bash
# Start semua services (Caddy + V8Box + Infrastructure)
docker-compose up -d

# Verify
docker-compose ps
```

#### 7. Check Logs

```bash
# Caddy logs (SSL certificate generation)
docker-compose logs -f caddy

# V8Box server logs
docker-compose logs -f v8box

# Infrastructure
docker-compose logs -f libsql valkey seaweedfs
```

#### 8. Access Dashboard

- `https://admin.yourdomain.com` - Admin Dashboard
- `https://api.yourdomain.com/run/hello` - Worker API
- `https://mysite.yourdomain.com` - Pages (after upload)

> [!NOTE]
> SSL certificate generation membutuhkan waktu ~30-60 detik pertama kali.

---

## 📊 Architecture Comparison

### Development Mode

```
Browser → localhost:8000 → Deno (manual) → server.ts
                              ↓
                         Infrastructure (Docker)
                         ├── LibSQL (8080)
                         ├── Valkey (6379)
                         └── SeaweedFS (8333)
```

### Production Mode

```
Browser → yourdomain.com:443 → Caddy (Docker)
             ↓ (with SSL)
         V8Box Server (Docker) → server.ts
             ↓
        Infrastructure (Docker)
        ├── LibSQL
        ├── Valkey
        └── SeaweedFS
```

---

## 🔄 Switching Between Modes

### Development → Production

```bash
# Stop manual server (Ctrl+C untuk deno task dev)

# Start full stack
docker-compose up -d
```

### Production → Development

```bash
# Stop full stack
docker-compose down

# Keep infrastructure only
docker-compose up -d libsql valkey seaweedfs

# Run server manually
deno task dev
```

---

## 🛠️ Maintenance

### Update Code (Production)

```bash
cd v8box

# Pull latest changes
git pull

# Restart V8Box server only
docker-compose restart v8box
```

### Update Docker Images

```bash
docker-compose pull
docker-compose up -d
```

### View Logs

```bash
# Caddy
docker-compose logs -f caddy

# V8Box
docker-compose logs -f v8box

# All services
docker-compose logs -f
```

### Backup

```bash
# Backup database
docker exec v8box-libsql sqld backup /backup/
docker cp v8box-libsql:/backup/. ./backups/libsql/

# Backup S3 data
tar -czf s3-backup-$(date +%Y%m%d).tar.gz \
  $(docker volume inspect v8box_seaweedfs-data -f '{{.Mountpoint}}')

# Backup code
tar -czf code-backup-$(date +%Y%m%d).tar.gz functions/ storage/pages/
```

---

## 🐛 Troubleshooting

### Production Issues

#### SSL Certificate Not Generated

**Check:**
```bash
docker-compose logs caddy | grep -i error
```

**Common fixes:**
1. Verify Cloudflare token is correct
2. Ensure DNS records exist and propagated
3. Check firewall allows port 443
4. Verify domain in `.env` matches Cloudflare

#### Cannot Access Dashboard

**Debug:**
```bash
# Check if Caddy is running
docker-compose ps caddy

# Check if responding
curl -v https://admin.yourdomain.com

# Check V8Box server
docker-compose logs v8box
```

#### Worker Not Found in Production

**Solution:**
```bash
# Ensure code is synced
git pull

# Restart server
docker-compose restart v8box

# Check files exist
docker exec v8box-server ls -la /app/functions/
```

### Development Issues

#### Port Already in Use

```bash
# Find process using port 8000
netstat -ano | findstr :8000

# Kill process (Windows)
taskkill /PID <PID> /F
```

#### Cannot Connect to Services

```bash
# Verify containers running
docker-compose ps

# Restart infrastructure
docker-compose restart libsql valkey seaweedfs
```

---

## 📚 Related Documentation

- [SETUP.md](file:///e:/git/github.com/v8box/SETUP.md) - Detailed configuration guide
- [install.sh](file:///e:/git/github.com/v8box/install.sh) - Auto-installer script
- [docker-compose.yml](file:///e:/git/github.com/v8box/docker-compose.yml) - Service definitions
- [Caddyfile](file:///e:/git/github.com/v8box/Caddyfile) - Reverse proxy config

---

**Recommendation:**
- **Development:** Use mode 1 untuk coding dan testing
- **Production:** Use mode 2 untuk deployment ke VPS dengan real domain

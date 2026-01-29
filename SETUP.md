# V8Box - Setup Guide

Panduan lengkap instalasi dan konfigurasi V8Box serverless platform.

## 📋 Quick Start

### 1. Start Docker Services

```bash
# Start LibSQL, Valkey, dan SeaweedFS
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

Minimal configuration:
```env
ADMIN_PASSWORD=your-secure-password
DOMAIN=localhost
```

### 3. Start V8Box Server

```bash
# Development mode (auto-reload)
deno task dev

# Or production mode
deno task start
```

### 4. Access Admin Dashboard

Open browser: `http://admin.localhost:8000`

Login dengan password dari `.env`

## 🔧 Detailed Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ADMIN_PASSWORD` | Admin dashboard password | `admin123` | ✅ |
| `LIBSQL_URL` | LibSQL database URL | `http://localhost:8080` | ✅ |
| `LIBSQL_AUTH_TOKEN` | LibSQL auth token | - | ❌ |
| `VALKEY_URL` | Valkey/Redis URL | `redis://localhost:6379` | ✅ |
| `S3_ENDPOINT` | SeaweedFS endpoint | `http://localhost:8333` | ✅ |
| `S3_ACCESS_KEY` | S3 access key | - | ✅ |
| `S3_SECRET_KEY` | S3 secret key | - | ✅ |
| `S3_BUCKET` | S3 bucket name | `v8box` | ✅ |
| `S3_REGION` | S3 region | `us-east-1` | ❌ |
| `DOMAIN` | Base domain | `domain.tld` | ✅ |
| `PORT` | Server port | `8000` | ❌ |

### SeaweedFS Initial Setup

SeaweedFS needs bucket creation:

```bash
# Install AWS CLI or use curl
# Create bucket
curl -X PUT http://localhost:8333/v8box

# Or using AWS CLI
aws --endpoint-url=http://localhost:8333 s3 mb s3://v8box
```

Note: SeaweedFS default credentials:
- Access Key: `any_key` (atau kosong)
- Secret Key: `any_secret` (atau kosong)

Update `.env` accordingly.

### DNS Configuration (Production)

For production deployment with real domain:

**Wildcard DNS Record:**
```
*.domain.tld  A  your-server-ip
```

**Specific Subdomains (alternative):**
```
admin.domain.tld   A  your-server-ip
api.domain.tld     A  your-server-ip
*.domain.tld       A  your-server-ip
```

### Hosts File (Local Development)

For local testing, edit hosts file:

**Windows:** `C:\Windows\System32\drivers\etc\hosts`
**Linux/Mac:** `/etc/hosts`

Add:
```
127.0.0.1  admin.localhost
127.0.0.1  api.localhost
127.0.0.1  test.localhost
```

## 🚀 Testing Installation

### Test 1: Admin Access

```bash
# Should show login page
curl http://admin.localhost:8000/
```

### Test 2: Worker Execution

```bash
# Test hello worker
curl http://api.localhost:8000/run/hello

# Expected response:
# {"success":true,"message":"Hello from V8Box!","visitorCount":1,...}
```

### Test 3: Pages Hosting

```bash
# Create test page
mkdir -p storage/pages/test
echo '<h1>Test Page</h1>' > storage/pages/test/index.html

# Access
curl http://test.localhost:8000/

# Expected: <h1>Test Page</h1>
```

### Test 4: Database

```bash
# Access database explorer
curl http://admin.localhost:8000/admin/database

# Or test via query worker
curl "http://api.localhost:8000/run/query"
```

### Test 5: S3 Storage

```bash
# Upload via worker
curl -X POST http://api.localhost:8000/run/upload \
  -H "Content-Type: application/json" \
  -d '{"filename":"test.txt","content":"Hello S3!"}'

# Check in admin
curl http://admin.localhost:8000/admin/s3
```

## 🐛 Troubleshooting

### Issue: Cannot connect to LibSQL

**Solution 1:** Check if LibSQL container is running
```bash
docker-compose ps libsql
docker-compose logs libsul
```

**Solution 2:** Wait for container to be ready (takes ~5 seconds)

**Solution 3:** Check firewall rules
```bash
# Test connection
curl http://localhost:8080/health
```

### Issue: Valkey connection refused

**Solution:** Verify Valkey is running and accessible
```bash
docker-compose ps valkey

# Test with redis-cli
docker exec -it v8box-valkey redis-cli ping
# Should return: PONG
```

### Issue: S3 bucket not found

**Solution:** Create bucket manually
```bash
curl -X PUT http://localhost:8333/v8box
```

### Issue: Subdomain not working

**Problem:** Browser cannot resolve `admin.localhost`

**Solution 1 (Recommended):** Use ports directly
- Admin: `http://localhost:8000/admin`
- API: `http://localhost:8000/run/...`

**Solution 2:** Edit hosts file (see DNS Configuration above)

**Solution 3:** Use real domain with proper DNS

### Issue: Worker import fails

**Symptoms:** `Worker not found` or import errors

**Solutions:**
1. Verify file exists: `ls -la functions/`
2. Check file extension: Must be `.ts`
3. Check file permissions: `chmod 644 functions/*.ts`
4. Verify worker exports default function

### Issue: Permission denied

**Symptoms:** Cannot create directories or write files

**Solution:** Run with proper permissions
```bash
# Create directories manually
mkdir -p functions storage/pages logs

# Set permissions
chmod -R 755 functions storage logs
```

## 📊 Monitoring & Logs

### View Server Logs

```bash
# Development mode shows logs in terminal
deno task dev

# Production: Use process manager or redirect
deno task start > server.log 2>&1 &

# View logs
tail -f server.log
```

### View Worker Execution Logs

```bash
# View specific worker logs
cat logs/hello.log

# Tail logs in real-time
tail -f logs/hello.log

# Last 50 lines
tail -n 50 logs/hello.log
```

### Docker Service Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f libsql
docker-compose logs -f valkey
docker-compose logs -f seaweedfs
```

## 🔒 Security Hardening

### Production Deployment

1. **Change Default Password**
   ```env
   ADMIN_PASSWORD=very-strong-password-here
   ```

2. **Enable HTTPS** (use reverse proxy like Nginx/Caddy)

3. **Restrict Access**
   - Admin dashboard: IP whitelist
   - API: Rate limiting
   - Database: Not exposed externally

4. **Regular Updates**
   ```bash
   # Update dependencies
   deno cache --reload deps.ts
   
   # Update Docker images
   docker-compose pull
   docker-compose up -d
   ```

5. **Backup Strategy**
   ```bash
   # Backup database
   docker exec v8box-libsql sqld backup /backup/
   
   # Backup storage
   tar -czf storage-backup.tar.gz storage/
   
   # Backup functions
   tar -czf functions-backup.tar.gz functions/
   ```

## 🎯 Next Steps

1. ✅ Create your first worker in `functions/`
2. ✅ Upload a static site via admin dashboard
3. ✅ Setup database tables
4. ✅ Configure Git webhook for auto-deployment
5. ✅ Setup monitoring and alerts

## 📚 Additional Resources

- [Deno Documentation](https://deno.land/manual)
- [Hono Framework](https://hono.dev/)
- [LibSQL Docs](https://github.com/libsql/libsql)
- [Valkey](https://valkey.io/)
- [SeaweedFS](https://github.com/seaweedfs/seaweedfs)

---

**Need Help?** Check existing issues or create new one on GitHub.

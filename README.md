# 🚀 V8Box

[![DB UI Smoke Test](https://github.com/ardantus/v8box/actions/workflows/db-ui-smoke.yml/badge.svg?branch=main)](https://github.com/ardantus/v8box/actions/workflows/db-ui-smoke.yml)

**V8Box** adalah platform *self-hosted serverless* minimalis yang menggabungkan kecepatan **V8 Isolates** dengan ekosistem penyimpanan cloud modern. Bayangkan memiliki Cloudflare (Workers, R2, D1, dan Pages) di dalam satu VPS pribadi Anda.

## ✨ Fitur Utama

* **V8 Workers:** Jalankan logika backend menggunakan TypeScript/Deno dengan *startup time* mendekati nol.
* **Static Pages Hosting:** Hosting website statis (Vite, React, Vue) via subdomain (production) atau subdirectory (localhost).
* **Auto-Unzip Deployment:** Cukup upload file `.zip`, sistem akan otomatis mengekstrak dan mendeploy.
* **S3-Compatible Storage:** Didukung oleh **SeaweedFS** (Apache 2.0) yang sangat ringan dan kencang.
* **Embedded SQL:** Database **LibSQL** terintegrasi untuk kebutuhan data relasional.
* **Automatic HTTPS:** SSL Wildcard otomatis untuk semua subdomain menggunakan **Caddy** dan Cloudflare DNS.
* **Mini Code Editor:** Edit kode Worker langsung dari Dashboard Admin.
* **Git Sync:** Dukungan webhook untuk sinkronisasi otomatis dari GitHub/GitLab.

---

## 🛠 Struktur Arsitektur

* **Gateway:** Caddy (Reverse Proxy & Auto SSL).
* **Runtime:** Deno (Engine V8).
* **Database:** LibSQL (SQLite-compatible).
* **Cache:** Valkey (Penerus Redis yang open-source).
* **Storage:** SeaweedFS (Object Storage).

---

## 🚀 Instalasi Cepat (One-Liner)

Jalankan perintah berikut di VPS Ubuntu/Debian Anda:

```bash
curl -sSL https://raw.githubusercontent.com/ardantus/v8box/main/install.sh | bash

```

---

## 📂 Alur Kerja Deployment

### 1. Worker (Backend)

Simpan file `.ts` Anda di folder `/functions`. Anda bisa mengaksesnya langsung via:
`https://api.yourdomain.com/run/nama-file`

Untuk local mode (`DOMAIN=localhost`), gunakan:
`http://localhost:8000/run/nama-file`

Contoh Worker sederhana:

```typescript
export default async (req, { db, cache }) => {
  await db.execute("INSERT INTO logs (msg) VALUES ('Hit from worker')");
  return { status: "success", message: "Hello from V8Box!" };
};

```

### 2. Pages (Frontend - Vite)

Bangun proyek Vite Anda secara lokal atau di GitHub Actions, ZIP folder `dist`, lalu kirim ke V8Box. Sistem akan mengekstraknya ke:
`https://nama-proyek.yourdomain.com`

Untuk local mode (`DOMAIN=localhost`), akses Pages via subdirectory:
`http://localhost:8000/pages/nama-proyek`

### 3. Integrasi GitHub Action

Tambahkan skrip ini di `.github/workflows/deploy.yml` untuk otomasi penuh:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: npm install && npm run build
      - name: Deploy to V8Box
        run: |
          cd dist && zip -r ../deploy.zip . && cd ..
          curl -X POST https://admin.yourdomain.com/api/deploy \
            -H "Authorization: Bearer ${{ secrets.V8BOX_TOKEN }}" \
            -F "project=my-site" \
            -F "file=@deploy.zip"

```

---

## 🔐 Keamanan & Akses

* **Admin Dashboard:** `https://admin.yourdomain.com`
* **Auth:** Menggunakan *Single-User Password* yang dikonfigurasi saat instalasi.
* **Data Isolation:** Setiap Pages dan Worker berjalan dalam *namespace* foldernya masing-masing.

---

## 🗄️ Database API (Multi Database)

Endpoint berikut tersedia di area admin (perlu login admin):

* **List database:** `GET /admin/database/databases`
* **Create database:** `POST /admin/database/databases` (body: `name`)
* **Delete database:** `DELETE /admin/database/databases/:database`
* **List table per database:** `GET /admin/database/databases/:database/tables`
* **Create table:** `POST /admin/database/databases/:database/tables` (body: `tableName`, `columns[]`)
* **Delete table:** `DELETE /admin/database/databases/:database/tables/:table`
* **Create row:** `POST /admin/database/databases/:database/tables/:table/rows` (body: `data`)
* **Read rows:** `GET /admin/database/databases/:database/tables/:table/rows`
* **Read single row:** `GET /admin/database/databases/:database/tables/:table/rows/:id`
* **Update row:** `PUT /admin/database/databases/:database/tables/:table/rows/:id` (body: `data`)
* **Delete row:** `DELETE /admin/database/databases/:database/tables/:table/rows/:id`
* **Search rows by filter:** `POST /admin/database/databases/:database/tables/:table/rows/search` (body: `where`, `whereArgs`, optional `limit`, `offset`, `orderBy`, `order`)
* **Update rows by filter:** `PUT /admin/database/databases/:database/tables/:table/rows` (body: `data`, `where`, `whereArgs`)
* **Delete rows by filter:** `DELETE /admin/database/databases/:database/tables/:table/rows` (body: `where`, `whereArgs`)
* **Query global:** `POST /admin/database/query/global`
* **Query per database:** `POST /admin/database/query/:database`
* **Backward compatible query:** `POST /admin/database/query` (body: `query`, optional `database`, default `global`)

`database=global` menjalankan query ke tabel global biasa. Database selain `global` dikelola sebagai namespace logis di koneksi LibSQL yang sama (dengan pemetaan tabel internal), sehingga tidak membutuhkan file `.db` terpisah.

Endpoint `:id` tetap tersedia untuk kasus tabel dengan primary key `id`, sementara endpoint berbasis `where` bisa dipakai untuk skema tabel apa pun.

### Contoh Pemakaian Cepat (cURL)

Contoh berikut mengasumsikan:

* Host admin lokal: `http://localhost:8080`
* Cookie login admin tersimpan di file: `/tmp/v8box.cookies`
* Header host admin opsional untuk mode subdomain: `Host: admin.localhost`

```bash
# 1) Create database
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/admin/database/databases \
  -d '{"name":"crm"}'

# 2) Create table di database crm
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/admin/database/databases/crm/tables \
  -d '{
    "tableName":"customers",
    "columns":[
      {"name":"id","type":"INTEGER","primaryKey":true,"autoIncrement":true},
      {"name":"name","type":"TEXT","nullable":false},
      {"name":"email","type":"TEXT","unique":true},
      {"name":"status","type":"TEXT","default":"active"}
    ]
  }'

# 3) Insert row
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/admin/database/databases/crm/tables/customers/rows \
  -d '{"data":{"name":"Andi","email":"andi@example.com","status":"active"}}'

# 4) Read rows
curl -sS -b /tmp/v8box.cookies \
  "http://localhost:8080/admin/database/databases/crm/tables/customers/rows?limit=20&orderBy=id&order=DESC"

# 5) Update by where (tidak tergantung kolom id)
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X PUT http://localhost:8080/admin/database/databases/crm/tables/customers/rows \
  -d '{"data":{"status":"inactive"},"where":"email = ?","whereArgs":["andi@example.com"]}'

# 6) Search by where
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/admin/database/databases/crm/tables/customers/rows/search \
  -d '{"where":"status = ?","whereArgs":["inactive"],"limit":10,"offset":0,"orderBy":"id","order":"DESC"}'

# 7) Delete by where
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X DELETE http://localhost:8080/admin/database/databases/crm/tables/customers/rows \
  -d '{"where":"email = ?","whereArgs":["andi@example.com"]}'

# 8) Query per-database
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/admin/database/query/crm \
  -d '{"query":"SELECT COUNT(*) AS total FROM customers"}'

# 9) Query global
curl -sS -b /tmp/v8box.cookies \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/admin/database/query/global \
  -d "{\"query\":\"SELECT name FROM sqlite_master WHERE type = 'table'\"}"
```

### Koleksi Postman

Koleksi siap import tersedia di [postman/v8box-database.postman_collection.json](postman/v8box-database.postman_collection.json).

Set variable berikut setelah import:

* `base_url` (default: `http://localhost:8080`)
* `admin_host_header` (opsional; isi `admin.localhost` jika pakai mode subdomain)
* `admin_password` (isi password admin Anda)
* `database`, `table`, `row_id`, `customer_email` sesuai skenario test

### Smoke Test Otomatis (Database UI)

Script smoke test untuk semua fungsi utama tombol database UI tersedia di [scripts/test-db-ui.sh](scripts/test-db-ui.sh).

Jalankan:

```bash
chmod +x scripts/test-db-ui.sh
./scripts/test-db-ui.sh

# atau shortcut via deno task
deno task test:db-ui

# restart service v8box lalu jalankan smoke test
deno task test:db-ui:full

# mode CI: output ringkas PASS/FAIL
deno task test:db-ui:ci

# fallback jika deno belum terpasang di host
bash scripts/test-db-ui-ci.sh
```

Opsional override environment variable:

```bash
BASE_URL=http://localhost:8080 \
COOKIE_HEADER='admin_session=authenticated' \
TEST_DB=uitestdb \
TEST_TABLE=uitestitems \
./scripts/test-db-ui.sh
```

Workflow CI otomatis tersedia di [.github/workflows/db-ui-smoke.yml](.github/workflows/db-ui-smoke.yml) dan berjalan saat `push`, `pull_request`, atau `workflow_dispatch`.

---

## 📄 Lisensi

Distribusi di bawah lisensi **Apache 2.0**. Gunakan secara bebas untuk kebutuhan internal maupun komersial.

Lihat [LICENSE](LICENSE) untuk detail lengkap.

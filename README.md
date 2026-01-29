# 🚀 V8Box

**V8Box** adalah platform *self-hosted serverless* minimalis yang menggabungkan kecepatan **V8 Isolates** dengan ekosistem penyimpanan cloud modern. Bayangkan memiliki Cloudflare (Workers, R2, D1, dan Pages) di dalam satu VPS pribadi Anda.

## ✨ Fitur Utama

* **V8 Workers:** Jalankan logika backend menggunakan TypeScript/Deno dengan *startup time* mendekati nol.
* **Static Pages Hosting:** Hosting website statis (Vite, React, Vue) otomatis via subdomain.
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

## 📄 Lisensi

Distribusi di bawah lisensi **Apache 2.0**. Gunakan secara bebas untuk kebutuhan internal maupun komersial.

Lihat [LICENSE](LICENSE) untuk detail lengkap.

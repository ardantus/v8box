import type { ServiceContext } from "../types.ts";

// Example worker: Hello World with database access
// Bisa dipanggil via:
// - Localhost mode: /run/hello
// - Domain mode: api.<domain>/run/hello
export default async function handler({ db, cache, s3 }: ServiceContext, params: Record<string, unknown> = {}) {
    try {
        // 1) Ambil counter pengunjung dari cache
        let count = await cache.get("visitor_count");
        count = count ? parseInt(count) : 0;
        count++;

        // 2) Simpan lagi counter terbaru ke cache
        await cache.set("visitor_count", count.toString());

        // 3) Simpan log request ke database
        //    - Buat tabel jika belum ada
        //    - Simpan payload params agar bisa dilihat kembali dari query SQL
        try {
            await db.execute(`
        CREATE TABLE IF NOT EXISTS visits (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          params TEXT
        )
      `);

            await db.execute({
                sql: "INSERT INTO visits (params) VALUES (?)",
                args: [JSON.stringify(params)]
            });
        } catch (dbError) {
            // Logging ke DB bersifat best-effort: worker tetap sukses walau DB error
            console.error("Database error:", dbError);
        }

        // 4) Kembalikan response JSON
        return {
            success: true,
            message: "Hello from V8Box!",
            visitorCount: count,
            params: params,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        // Error utama worker
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}

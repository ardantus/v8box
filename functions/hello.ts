// Example worker: Hello World with database access
export default async function handler({ db, cache, s3 }, params) {
    try {
        // Get visitor count from cache
        let count = await cache.get("visitor_count");
        count = count ? parseInt(count) : 0;
        count++;

        // Update cache
        await cache.set("visitor_count", count.toString());

        // Log to database (create table if not exists)
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
            console.error("Database error:", dbError);
        }

        return {
            success: true,
            message: "Hello from V8Box!",
            visitorCount: count,
            params: params,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

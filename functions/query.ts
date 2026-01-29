// Example worker: Database Query
// Query database and return results
export default async function handler({ db, cache, s3 }, params) {
    try {
        const { query, limit = 10 } = params;

        // If no query provided, return stats
        if (!query) {
            // Get table list
            const tables = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            );

            return {
                success: true,
                message: "Provide 'query' parameter to execute SQL",
                availableTables: tables.rows.map(r => r.name),
                example: "/run/query?query=SELECT * FROM visits LIMIT 10"
            };
        }

        // Execute query
        const result = await db.execute(query);

        // Cache result for 60 seconds
        const cacheKey = `query:${query}`;
        await cache.setex(cacheKey, 60, JSON.stringify(result.rows));

        return {
            success: true,
            rows: result.rows,
            columns: result.columns,
            rowCount: result.rows.length,
            cached: true,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

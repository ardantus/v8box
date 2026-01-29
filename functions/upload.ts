// Example worker: S3 Upload
// Upload file to SeaweedFS S3 storage
export default async function handler({ db, cache, s3 }, params) {
    try {
        const { filename, content } = params;

        if (!filename || !content) {
            return {
                success: false,
                error: "Missing filename or content parameter"
            };
        }

        // Upload to S3
        const { PutObjectCommand } = await import("@aws-sdk/client-s3");

        const command = new PutObjectCommand({
            Bucket: Deno.env.get("S3_BUCKET") || "v8box",
            Key: filename,
            Body: new TextEncoder().encode(content),
            ContentType: "text/plain"
        });

        await s3.send(command);

        // Log to cache
        await cache.set(`upload:${filename}`, new Date().toISOString());

        return {
            success: true,
            message: "File uploaded successfully",
            filename: filename,
            size: content.length,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

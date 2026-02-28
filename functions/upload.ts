// Example worker: S3 Upload
// Upload file to SeaweedFS S3 storage
export default async function handler({ db, cache, s3 }, params) {
    try {
        const { filename, content } = params;
        const bucket = params.bucket ||
            Deno.env.get("S3_FUNCTIONS_BUCKET") ||
            Deno.env.get("S3_DEFAULT_BUCKET") ||
            Deno.env.get("S3_BUCKET") ||
            "v8box";

        if (!filename || !content) {
            return {
                success: false,
                error: "Missing filename or content parameter"
            };
        }

        // Upload to S3
        const { PutObjectCommand } = await import("@aws-sdk/client-s3");

        const command = new PutObjectCommand({
            Bucket: bucket,
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
            bucket,
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

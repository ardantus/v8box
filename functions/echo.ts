import type { ServiceContext } from "../types.ts";

// Example worker: Echo Params
// Tujuan:
// - Menampilkan ulang input params untuk debugging cepat
// - Memberi metadata sederhana (timestamp + method)
// Cara akses:
// - Localhost mode: /run/echo?name=ardan
// - Domain mode: api.<domain>/run/echo?name=ardan
export default async function handler(_ctx: ServiceContext, params: Record<string, unknown> = {}) {
    try {
        // Ambil URL request jika dikirim dari caller (opsional)
        // (Berguna jika ingin tahu query asli yang masuk)
        const source = typeof params.url === "string" ? params.url : null;

        return {
            success: true,
            message: "Echo worker executed",
            received: params,
            source,
            timestamp: new Date().toISOString(),
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

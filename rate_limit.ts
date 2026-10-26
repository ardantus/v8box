// ============================================================================
// CLOUDFLARE COMPATIBLE RATE LIMITING (Apache / Nginx)
// ============================================================================
// Cloudflare-style rate limiting: per-IP, per-API-key, per-endpoint
// Run: deno run --allow-env --allow-read --allow-write rate_limit.ts
// ============================================================================
import { Redis, connect } from "./deps.ts";

export interface RateLimitRule {
  id: string;
  limit: number; // max requests
  window: number; // seconds
  keyPrefix: string; // per-IP, per-API-Key, etc.
  endpoint?: string;
  method?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
  current: number;
  limit: number;
}

export interface RateLimiter {
  config: RateLimitRule[];
  client: Redis;
  connect(): Promise<void>;
  check(key: string, ruleId: string, endpoint: string, method: string): Promise<RateLimitResult>;
  getStats(): Promise<Record<string, unknown>>;
}

export class RateLimiter implements RateLimiter {
  client: Redis;
  config: RateLimitRule[];

  constructor(redisUrl?: string, rules?: RateLimitRule[]) {
    this.client = connect({
      hostname: redisUrl?.split("//")[1]?.split(":")[0] || "localhost",
      port: parseInt(redisUrl?.split(":")[2]?.split("/")[0] || "6379"),
    });
    this.config = rules || [
      {
        id: "default",
        limit: 100,
        window: 60,
        keyPrefix: "rate:default",
      },
      {
        id: "api",
        limit: 50,
        window: 60,
        keyPrefix: "rate:api",
        endpoint: "/run/*",
        method: "POST",
      },
      {
        id: "admin",
        limit: 30,
        window: 60,
        keyPrefix: "rate:admin",
        endpoint: "/admin/*",
        method: "GET",
      },
    ];
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  private getKey(ip: string, rule: RateLimitRule): string {
    return `${rule.keyPrefix}:${ip}`;
  }

  async check(key: string, ruleId: string, endpoint: string, method: string): Promise<RateLimitResult> {
    const rule = this.config.find(r => r.id === ruleId);
    if (!rule) {
      return {
        allowed: true,
        remaining: 100,
        resetAt: Date.now() + 60000,
        current: 0,
        limit: 100,
      };
    }

    const fullKey = this.getKey(key, rule);
    const now = Date.now();
    const windowMs = rule.window * 1000;

    // Get current count
    const raw = await this.client.get(fullKey);
    let count = 0;
    let windowStart = 0;

    if (raw) {
      try {
        const data = JSON.parse(raw) as { count: number; windowStart: number };
        count = data.count;
        windowStart = data.windowStart;
      } catch {
        count = 0;
      }
    }

    // Check if window expired
    if (now - windowStart > windowMs) {
      count = 0;
      windowStart = now;
    }

    count += 1;
    const resetAt = windowStart + windowMs;
    const remaining = Math.max(0, rule.limit - count);

    // Update Redis
    await this.client.set(
      fullKey,
      JSON.stringify({ count, windowStart }),
      { px: windowMs } // millisecond precision
    );
    await this.client.expire(fullKey, rule.window + 1);

    return {
      allowed: count <= rule.limit,
      remaining,
      resetAt,
      current: count,
      limit: rule.limit,
    };
  }

  async getStats(): Promise<Record<string, unknown>> {
    const statsKey = "rate:limits:stats";
    const raw = await this.client.hGetAll(statsKey);
    return raw as Record<string, unknown>;
  }
}

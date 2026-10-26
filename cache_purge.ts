// ============================================================================
// CLOUDFLARE COMPATIBLE CACHE PURGING (Redis)
// ============================================================================
// Simulates Cloudflare Cache Purging: tag-based invalidation, wildcard purge
// Run: deno run --allow-env --allow-read --allow-write cache_purge.ts
// ============================================================================
import { Redis, connect } from "./deps.ts";

export interface CacheKey {
  key: string;
  tags: string[];
  ttl?: number;
  createdAt: number;
}

export interface CacheStats {
  totalKeys: number;
  taggedKeys: number;
  lastPurged: number;
  totalPurges: number;
}

export interface CacheManager {
  client: Redis;
  prefix: string;
  connect(): Promise<void>;
  set(key: string, value: unknown, opts?: { tags?: string[]; ttl?: number }): Promise<void>;
  get(key: string): Promise<unknown | null>;
  has(key: string): Promise<boolean>;
  delete(key: string): Promise<boolean>;
  purgeByTag(tags: string[]): Promise<number>;
  purgeMatching(pattern: string): Promise<number>;
  purgeMatchingPrefix(prefix: string): Promise<number>;
  stats(): Promise<CacheStats>;
}

export class RedisCache implements CacheManager {
  client: Redis;
  prefix: string = "cache:";

  constructor(redisUrl?: string, customPrefix?: string) {
    this.client = connect({
      hostname: redisUrl?.split("//")[1]?.split(":")[0] || "localhost",
      port: parseInt(redisUrl?.split(":")[2]?.split("/")[0] || "6379"),
    });
    if (customPrefix) {
      this.prefix = customPrefix;
    }
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  async set(key: string, value: unknown, opts: { tags?: string[]; ttl?: number } = {}): Promise<void> {
    const fullKey = `${this.prefix}${key}`;
    const tags = opts.tags || [];
    const ttl = opts.ttl || 3600; // default 1 hour

    // Store value
    await this.client.set(fullKey, JSON.stringify(value));
    await this.client.expire(fullKey, ttl);

    // Store tags mapping
    for (const tag of tags) {
      const tagKey = `${this.prefix}tags:${tag}`;
      await this.client.sAdd(tagKey, key);
      await this.client.expire(tagKey, ttl);
    }
  }

  async get(key: string): Promise<unknown | null> {
    const fullKey = `${this.prefix}${key}`;
    const raw = await this.client.get(fullKey);
    if (!raw) return null;

    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  async has(key: string): Promise<boolean> {
    const fullKey = `${this.prefix}${key}`;
    const exists = await this.client.exists(fullKey);
    return exists === 1;
  }

  async delete(key: string): Promise<boolean> {
    const fullKey = `${this.prefix}${key}`;
    const exists = await this.client.exists(fullKey);
    if (exists === 1) {
      await this.client.del(fullKey);
      // Delete associated tags
      const tagKeys = await this.client.keys(`${this.prefix}tags:*`);
      for (const tagKey of tagKeys) {
        await this.client.sRem(tagKey, key);
      }
      return true;
    }
    return false;
  }

  async purgeByTag(tags: string[]): Promise<number> {
    let totalPurged = 0;

    for (const tag of tags) {
      const tagKey = `${this.prefix}tags:${tag}`;
      const keys = await this.client.sMembers(tagKey);
      if (keys.length === 0) continue;

      const pipeline = this.client.multi();
      for (const key of keys) {
        pipeline.del(`${this.prefix}${key}`);
      }
      await pipeline.exec();

      // Clear tag set
      await this.client.del(tagKey);
      totalPurged += keys.length;
    }

    // Update stats
    const statsKey = `${this.prefix}stats`;
    const current = await this.client.get(statsKey);
    const stats = current ? parseInt(current) : 0;
    await this.client.set(statsKey, String(stats + totalPurged));
    await this.client.expire(statsKey, 86400);

    return totalPurged;
  }

  async purgeMatching(pattern: string): Promise<number> {
    const fullPattern = `${this.prefix}*`;
    const keys = await this.client.keys(fullPattern);
    if (keys.length === 0) return 0;

    const pipeline = this.client.multi();
    for (const key of keys) {
      pipeline.del(key);
    }
    await pipeline.exec();

    // Update stats
    const statsKey = `${this.prefix}stats`;
    const current = await this.client.get(statsKey);
    const stats = current ? parseInt(current) : 0;
    await this.client.set(statsKey, String(stats + keys.length));
    await this.client.expire(statsKey, 86400);

    return keys.length;
  }

  async purgeMatchingPrefix(prefix: string): Promise<number> {
    const fullPrefix = `${this.prefix}${prefix}`;
    const keys = await this.client.keys(`${fullPrefix}*`);
    if (keys.length === 0) return 0;

    const pipeline = this.client.multi();
    for (const key of keys) {
      pipeline.del(key);
    }
    await pipeline.exec();

    // Update stats
    const statsKey = `${this.prefix}stats`;
    const current = await this.client.get(statsKey);
    const stats = current ? parseInt(current) : 0;
    await this.client.set(statsKey, String(stats + keys.length));
    await this.client.expire(statsKey, 86400);

    return keys.length;
  }

  async stats(): Promise<CacheStats> {
    const pattern = `${this.prefix}tags:*`;
    const tagKeys = await this.client.keys(pattern);
    let taggedKeys = 0;

    const pipeline = this.client.multi();
    for (const tagKey of tagKeys) {
      pipeline.sCard(tagKey);
    }
    const results = await pipeline.exec();
    for (const result of results) {
      if (result && typeof result[1] === "number") {
        taggedKeys += result[1] as number;
      }
    }

    const statsKey = `${this.prefix}stats`;
    const cached = await this.client.get(statsKey);
    const totalPurges = cached ? parseInt(cached) : 0;

    return {
      totalKeys: tagKeys.length,
      taggedKeys,
      lastPurged: Date.now(),
      totalPurges,
    };
  }
}

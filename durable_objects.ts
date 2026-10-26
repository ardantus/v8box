// ============================================================================
// CLOUDFLARE COMPATIBLE DURABLE OBJECTS (Redis)
// ============================================================================
// Simulates Cloudflare Durable Objects: stateful, auto-scaled, consistent
// Run: deno run --allow-env --allow-read --allow-write durable_objects.ts
// ============================================================================
import { Redis, connect } from "./deps.ts";

export type DurableObjectId = string;
export type Status = "active" | "suspended" | "terminated";

export interface DurableObjectState<T = unknown> {
  id: DurableObjectId;
  name: string;
  status: Status;
  data: T;
  createdAt: number;
  updatedAt: number;
  version: number;
}

export interface DurableObjectManager<T = unknown> {
  config: {
    prefix: string;
    redisUrl: string;
    ttl: number;
  };
  client: Redis;
  connect(): Promise<void>;
  createId(name?: string): DurableObjectId;
  get(id: DurableObjectId): Promise<DurableObjectState<T> | null>;
  put(id: DurableObjectId, data: T): Promise<void>;
  delete(id: DurableObjectId): Promise<boolean>;
  list(names?: string[]): Promise<DurableObjectState<T>[]>;
}

function generateDurableId(name?: string): DurableObjectId {
  const prefix = name ? `${name}:` : "";
  return `${prefix}${crypto.randomUUID()}`;
}

export class RedisDurableObject<T = unknown> implements DurableObjectManager<T> {
  config: {
    prefix: string;
    redisUrl: string;
    ttl: number;
  };
  client: Redis;

  constructor(config: { prefix?: string; redisUrl?: string; ttl?: number }) {
    this.config = {
      prefix: config.prefix || "durable:",
      redisUrl: config.redisUrl || "redis://localhost:6379",
      ttl: config.ttl || 86400, // 24 hours
    };
    this.client = connect({
      hostname: new URL(config.redisUrl).hostname || "localhost",
      port: parseInt(new URL(config.redisUrl).port || "6379"),
    });
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  createId(name?: string): DurableObjectId {
    return generateDurableId(name);
  }

  async get(id: DurableObjectId): Promise<DurableObjectState<T> | null> {
    const key = `${this.config.prefix}${id}`;
    const raw = await this.client.get(key);
    if (!raw) return null;

    try {
      const data = JSON.parse(raw) as T;
      return {
        id,
        name: id.replace(`${this.config.prefix}`, ""),
        status: "active",
        data,
        createdAt: 0,
        updatedAt: 0,
        version: 0,
      };
    } catch {
      return null;
    }
  }

  async put(id: DurableObjectId, data: T): Promise<void> {
    const key = `${this.config.prefix}${id}`;
    const now = Date.now();

    const state: DurableObjectState<T> = {
      id,
      name: id.replace(`${this.config.prefix}`, ""),
      status: "active",
      data,
      createdAt: 0,
      updatedAt: now,
      version: await this.client.incr(`${key}:version`),
    };

    await this.client.set(key, JSON.stringify(data));
    await this.client.expire(key, this.config.ttl);
    await this.client.expire(`${key}:version`, this.config.ttl);
  }

  async delete(id: DurableObjectId): Promise<boolean> {
    const key = `${this.config.prefix}${id}`;
    const exists = await this.client.exists(key);
    if (exists) {
      await this.client.del(key);
      await this.client.del(`${key}:version`);
    }
    return exists === 1;
  }

  async list(names?: string[]): Promise<DurableObjectState<T>[]> {
    const pattern = names && names.length > 0
      ? `${this.config.prefix}${names.map(n => escapeRegex(n)).join("|")}:*`
      : `${this.config.prefix}*`;

    const keys = await this.client.keys(pattern);
    const states: DurableObjectState<T>[] = [];

    for (const key of keys) {
      const raw = await this.client.get(key);
      if (raw) {
        try {
          const data = JSON.parse(raw) as T;
          states.push({
            id: key.replace(`${this.config.prefix}`, ""),
            name: key.replace(`${this.config.prefix}`, ""),
            status: "active",
            data,
            createdAt: 0,
            updatedAt: 0,
            version: 0,
          });
        } catch {
          // skip malformed
        }
      }
    }

    return states;
  }
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

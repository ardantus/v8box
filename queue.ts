// ============================================================================
// CLOUDFLARE COMPATIBLE QUEUES (Valkey/ Redis)
// ============================================================================
// Simulates Cloudflare Queues: task queue with retry, DLQ, delay, batch
// Run: deno run --allow-env --allow-read --allow-write queue.ts
// ============================================================================
import { Redis, connect } from "./deps.ts";
import { join, extname, exists } from "./deps.ts";

interface QueueConfig {
  name: string;
  delay?: number; // ms
  retryLimit?: number;
  rateLimit?: number; // ops per second
}

interface QueuedTask {
  id: string;
  queue: string;
  payload: unknown;
  attempts: number;
  maxAttempts: number;
  delay: number;
  status: "queued" | "processing" | "completed" | "failed";
  createdAt: number;
  updatedAt: number;
  error?: string;
  processedAt?: number;
}

interface QueueManager {
  config: QueueConfig;
  client: Redis;
  connect(): Promise<void>;
  enqueue(payload: unknown, opts?: Partial<QueueConfig>): Promise<string>;
  dequeue(): Promise<QueuedTask | null>;
  ack(task: QueuedTask): Promise<void>;
  nack(task: QueuedTask, retry: boolean): Promise<void>;
  dlq(task: QueuedTask): Promise<void>;
  getStats(): Promise<Record<string, unknown>>;
}

function generateId(): string {
  return `${crypto.randomUUID()}`;
}

export class ValkeyQueue implements QueueManager {
  config: QueueConfig;
  client: Redis;

  constructor(config: QueueConfig) {
    this.config = {
      name: config.name || "default",
      delay: config.delay || 0,
      retryLimit: config.retryLimit || 3,
      rateLimit: config.rateLimit || 100,
    };
    this.client = connect({
      hostname: "127.0.0.1",
      port: 6379,
    });
  }

  async connect(): Promise<void> {
    await this.client.connect();
    // Create queue keys
    const [queueKey, dlqKey, statsKey] = [
      `queue:${this.config.name}`,
      `dlq:${this.config.name}`,
      `stats:${this.config.name}`,
    ];
    // Set up keys with TTL
    await this.client.set(`${queueKey}:meta`, JSON.stringify(this.config));
    await this.client.expire(`${queueKey}:meta`, 3600);
  }

  async enqueue(payload: unknown, opts?: Partial<QueueConfig>): Promise<string> {
    const id = generateId();
    const task: QueuedTask = {
      id,
      queue: this.config.name,
      payload,
      attempts: 0,
      maxAttempts: opts?.retryLimit ?? this.config.retryLimit,
      delay: opts?.delay ?? this.config.delay,
      status: "queued",
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    const queueKey = `queue:${this.config.name}`;
    const dlqKey = `dlq:${this.config.name}`;

    // Push to queue (RPUSH)
    await this.client.rPush(queueKey, JSON.stringify(task));
    await this.client.expire(queueKey, 86400);

    // Update stats
    const stats = await this.getStats();
    await this.client.hIncrBy(statsKey, "total_enqueued", 1);

    return id;
  }

  async dequeue(): Promise<QueuedTask | null> {
    const queueKey = `queue:${this.config.name}`;
    const dlqKey = `dlq:${this.config.name}`;

    // Try to get from main queue
    const raw = await this.client.lPop(queueKey);
    if (!raw) return null;

    let task: QueuedTask;
    try {
      task = JSON.parse(raw as string);
    } catch {
      // Malformed task, reject it
      await this.client.rPush(dlqKey, raw as string);
      await this.client.hIncrBy(`stats:${this.config.name}`, "malformed", 1);
      return null;
    }

    // Check delay
    const now = Date.now();
    if (task.delay > 0) {
      const waitUntil = task.createdAt + task.delay;
      if (now < waitUntil) {
        // Retry later
        const retryAt = now + 1000; // retry in 1s
        const retryTask = { ...task, scheduledFor: retryAt };
        await this.client.rPush(`queue:${this.config.name}:scheduled`, JSON.stringify(retryTask));
        return null;
      }
    }

    // Mark as processing
    task.status = "processing";
    task.attempts += 1;
    task.updatedAt = Date.now();
    await this.client.set(`task:${this.config.name}:${task.id}`, JSON.stringify(task));
    await this.client.expire(`task:${this.config.name}:${task.id}`, 3600);

    // Update stats
    const stats = await this.getStats();
    await this.client.hIncrBy(statsKey, "total_dequeued", 1);

    return task;
  }

  async ack(task: QueuedTask): Promise<void> {
    const queueKey = `queue:${this.config.name}`;
    const dlqKey = `dlq:${this.config.name}`;
    const statsKey = `stats:${this.config.name}`;

    task.status = "completed";
    task.processedAt = Date.now();
    task.updatedAt = Date.now();

    await this.client.set(`task:${this.config.name}:${task.id}`, JSON.stringify(task));
    await this.client.expire(`task:${this.config.name}:${task.id}`, 86400);

    await this.client.hIncrBy(statsKey, "total_acked", 1);
    await this.client.hIncrBy(statsKey, "total_completed", 1);
  }

  async nack(task: QueuedTask, retry: boolean): Promise<void> {
    const dlqKey = `dlq:${this.config.name}`;
    const statsKey = `stats:${this.config.name}`;

    if (retry && task.attempts < task.maxAttempts) {
      // Retry: push to front of queue
      const retryTask = {
        ...task,
        status: "queued",
        attempts: task.attempts + 1,
        updatedAt: Date.now(),
      };
      await this.client.lPush(queueKey, JSON.stringify(retryTask));
      await this.client.expire(queueKey, 86400);
      await this.client.hIncrBy(statsKey, "total_nacked", 1);
      return;
    }

    // Move to DLQ
    task.status = "failed";
    task.error = "Max retries exceeded";
    task.updatedAt = Date.now();
    await this.client.set(`task:${this.config.name}:${task.id}`, JSON.stringify(task));
    await this.client.expire(`task:${this.config.name}:${task.id}`, 86400);

    await this.client.rPush(dlqKey, JSON.stringify(task));
    await this.client.expire(dlqKey, 86400);
    await this.client.hIncrBy(statsKey, "total_nacked", 1);
    await this.client.hIncrBy(statsKey, "total_failed", 1);
  }

  async dlq(task: QueuedTask): Promise<void> {
    const dlqKey = `dlq:${this.config.name}`;
    task.status = "failed";
    task.error = "Moved to DLQ";
    task.updatedAt = Date.now();
    await this.client.set(`task:${this.config.name}:${task.id}`, JSON.stringify(task));
    await this.client.rPush(dlqKey, JSON.stringify(task));
    await this.client.expire(dlqKey, 86400);
    await this.client.hIncrBy(`stats:${this.config.name}`, "total_dlq", 1);
  }

  async getStats(): Promise<Record<string, unknown>> {
    const statsKey = `stats:${this.config.name}`;
    const raw = await this.client.hGetAll(statsKey);
    return raw as Record<string, unknown>;
  }
}

// ============================================================================
// CLOUDFLARE COMPATIBLE FEATURES - CLI TOOL
// ============================================================================
// Implements Cloudflare-designed features for self-hosted infrastructure:
//  1. Queues (Valkey-based task queue)
//  2. Durable Objects (Redis-based state)
//  3. Cache Purging (Redis-based invalidation)
//  4. Rate Limiting (per-IP, per-API-key)
// ============================================================================
import { Redis, connect } from "./deps.ts";
import { ValkeyQueue } from "./queue.ts";
import { RedisDurableObject } from "./durable_objects.ts";
import { RedisCache } from "./cache_purge.ts";
import { RateLimiter } from "./rate_limit.ts";

async function main(): Promise<void> {
  const args = Deno.args;
  const command = args[0];

  if (!command) {
    console.log(`
🧊 Cloudflare Compatible Features CLI
Usage:
  deno run --allow-env --allow-read --allow-write cli.ts <command> [options]

Commands:
  queue:send     Send a task to the queue
  queue:pull     Pull a task from the queue
  queue:stats    Show queue statistics
  obj:create     Create a durable object
  obj:put        Put data into a durable object
  obj:get        Get data from a durable object
  obj:list       List durable objects
  cache:set      Set a cache entry
  cache:get      Get a cache entry
  cache:purge    Purge cache by tag or prefix
  cache:stats    Show cache statistics
  rate:check     Check rate limit for an IP/key
  rate:stats     Show rate limiting statistics

Examples:
  deno run --allow-env --allow-read --allow-write cli.ts queue:send --queue api --payload {"cmd":"deploy"}
  deno run --allow-env --allow-read --allow-write cli.ts queue:pull --queue api
`);
    Deno.exit(0);
  }

  try {
    switch (command) {
      case "queue:send": {
        const queueName = args.find(a => a.startsWith("--queue="));
        const payload = args.find(a => a.startsWith("--payload="));
        if (!queueName || !payload) {
          console.error("❌ Missing required args: --queue=NAME --payload={...}");
          Deno.exit(1);
        }
        const queue = new ValkeyQueue({ name: queueName.replace("--queue=", "") });
        await queue.connect();
        const taskId = await queue.enqueue(JSON.parse(payload.replace("--payload=", "")));
        console.log(`✅ Task enqueued: ${taskId}`);
        break;
      }

      case "queue:pull": {
        const queueName = args.find(a => a.startsWith("--queue="));
        if (!queueName) {
          console.error("❌ Missing required arg: --queue=NAME");
          Deno.exit(1);
        }
        const queue = new ValkeyQueue({ name: queueName.replace("--queue=", "") });
        await queue.connect();
        const task = await queue.dequeue();
        if (task) {
          console.log(`✅ Task: ${task.id} - ${JSON.stringify(task.payload)}`);
          await queue.ack(task);
          console.log(`✅ Task acked: ${task.id}`);
        } else {
          console.log("⏳ No tasks in queue");
        }
        break;
      }

      case "queue:stats": {
        const queueName = args.find(a => a.startsWith("--queue="));
        const queue = new ValkeyQueue({ name: queueName?.replace("--queue=", "") || "default" });
        await queue.connect();
        const stats = await queue.getStats();
        console.log("📊 Queue Stats:", JSON.stringify(stats, null, 2));
        break;
      }

      case "obj:create": {
        const objName = args.find(a => a.startsWith("--name="));
        if (!objName) {
          console.error("❌ Missing required arg: --name=OBJECT_NAME");
          Deno.exit(1);
        }
        const obj = new RedisDurableObject<unknown>({ prefix: "durable" });
        await obj.connect();
        const id = obj.createId(objName.replace("--name=", ""));
        const data = { status: "created", timestamp: Date.now() };
        await obj.put(id, data);
        console.log(`✅ Durable object created: ${id}`);
        break;
      }

      case "obj:put": {
        const objName = args.find(a => a.startsWith("--name="));
        const data = args.find(a => a.startsWith("--data="));
        if (!objName || !data) {
          console.error("❌ Missing required args: --name=OBJECT_NAME --data={...}");
          Deno.exit(1);
        }
        const obj = new RedisDurableObject<unknown>({ prefix: "durable" });
        await obj.connect();
        const id = obj.createId(objName.replace("--name=", ""));
        await obj.put(id, JSON.parse(data.replace("--data=", "")));
        console.log(`✅ Durable object updated: ${id}`);
        break;
      }

      case "obj:get": {
        const objName = args.find(a => a.startsWith("--name="));
        if (!objName) {
          console.error("❌ Missing required arg: --name=OBJECT_NAME");
          Deno.exit(1);
        }
        const obj = new RedisDurableObject<unknown>({ prefix: "durable" });
        await obj.connect();
        const id = obj.createId(objName.replace("--name=", ""));
        const state = await obj.get(id);
        console.log(`📦 Durable object: ${JSON.stringify(state)}`);
        break;
      }

      case "obj:list": {
        const obj = new RedisDurableObject<unknown>({ prefix: "durable" });
        await obj.connect();
        const states = await obj.list();
        console.log(`📦 Durable objects: ${JSON.stringify(states, null, 2)}`);
        break;
      }

      case "cache:set": {
        const key = args.find(a => a.startsWith("--key="));
        const value = args.find(a => a.startsWith("--value="));
        if (!key || !value) {
          console.error("❌ Missing required args: --key=KEY --value={...}");
          Deno.exit(1);
        }
        const cache = new RedisCache();
        await cache.connect();
        await cache.set(key.replace("--key=", ""), JSON.parse(value.replace("--value=", "")));
        console.log(`✅ Cache set: ${key.replace("--key=", "")}`);
        break;
      }

      case "cache:get": {
        const key = args.find(a => a.startsWith("--key="));
        if (!key) {
          console.error("❌ Missing required arg: --key=KEY");
          Deno.exit(1);
        }
        const cache = new RedisCache();
        await cache.connect();
        const val = await cache.get(key.replace("--key=", ""));
        console.log(`📦 Cache: ${JSON.stringify(val)}`);
        break;
      }

      case "cache:purge": {
        const tag = args.find(a => a.startsWith("--tag="));
        const pattern = args.find(a => a.startsWith("--pattern="));
        const cache = new RedisCache();
        await cache.connect();
        if (tag) {
          const count = await cache.purgeByTag([tag.replace("--tag=", "")]);
          console.log(`🗑️ Purged ${count} keys by tag '${tag.replace("--tag=", "")}'`);
        } else if (pattern) {
          const count = await cache.purgeMatching(pattern.replace("--pattern=", ""));
          console.log(`🗑️ Purged ${count} keys matching pattern '${pattern.replace("--pattern=", "")}'`);
        } else {
          console.error("❌ Missing required arg: --tag=TAG or --pattern=PATTERN");
          Deno.exit(1);
        }
        break;
      }

      case "cache:stats": {
        const cache = new RedisCache();
        await cache.connect();
        const stats = await cache.stats();
        console.log("📊 Cache Stats:", JSON.stringify(stats, null, 2));
        break;
      }

      case "rate:check": {
        const ip = args.find(a => a.startsWith("--ip="));
        const ruleId = args.find(a => a.startsWith("--rule="));
        const endpoint = args.find(a => a.startsWith("--endpoint="));
        if (!ip || !ruleId) {
          console.error("❌ Missing required args: --ip=IP --rule=RULE_ID [--endpoint=/path]");
          Deno.exit(1);
        }
        const limiter = new RateLimiter();
        await limiter.connect();
        const result = await limiter.check(ip.replace("--ip=", ""), ruleId.replace("--rule=", ""), endpoint?.replace("--endpoint=", "") || "/", "GET");
        console.log("🔐 Rate Limit:", JSON.stringify(result, null, 2));
        break;
      }

      case "rate:stats": {
        const limiter = new RateLimiter();
        await limiter.connect();
        const stats = await limiter.getStats();
        console.log("📊 Rate Stats:", JSON.stringify(stats, null, 2));
        break;
      }

      default:
        console.error(`❌ Unknown command: ${command}`);
        Deno.exit(1);
    }
  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
    Deno.exit(1);
  }
}

if (import.meta.main) {
  main();
}

import {
    Hono,
    getCookie,
    setCookie,
    deleteCookie,
    createClient,
    connect,
    S3Client,
    ListObjectsV2Command,
    ListBucketsCommand,
    DeleteObjectCommand,
    DeleteBucketCommand,
    CopyObjectCommand,
    CreateBucketCommand,
    PutObjectCommand,
    GetObjectCommand,
    JSZip,
    exists,
    join,
    extname,
    ensureDir,
} from "./deps.ts";
  import type { Context, Next } from "./deps.ts";
import type { ServiceContext, ApiResponse, ExecutionLog, PageProject, S3Object, S3Bucket } from "./types.ts";

// ============================================================================
// CONFIGURATION
// ============================================================================

const s3DefaultBucket = Deno.env.get("S3_DEFAULT_BUCKET") || Deno.env.get("S3_BUCKET") || "v8box";
const s3ProjectsBucket = Deno.env.get("S3_PROJECTS_BUCKET") || `${s3DefaultBucket}-projects`;
const s3FunctionsBucket = Deno.env.get("S3_FUNCTIONS_BUCKET") || `${s3DefaultBucket}-functions`;

const config = {
    adminPassword: Deno.env.get("ADMIN_PASSWORD") || "admin123",
    libsqlUrl: Deno.env.get("LIBSQL_URL") || "http://localhost:8080",
    libsqlAuthToken: Deno.env.get("LIBSQL_AUTH_TOKEN"),
    valkeyUrl: Deno.env.get("VALKEY_URL") || "redis://localhost:6379",
    s3Endpoint: Deno.env.get("S3_ENDPOINT") || "http://localhost:8333",
    s3AccessKey: Deno.env.get("S3_ACCESS_KEY") || "",
    s3SecretKey: Deno.env.get("S3_SECRET_KEY") || "",
  s3DefaultBucket,
  s3ProjectsBucket,
  s3FunctionsBucket,
    s3Region: Deno.env.get("S3_REGION") || "us-east-1",
    domain: Deno.env.get("DOMAIN") || "domain.tld",
    port: parseInt(Deno.env.get("PORT") || "8000"),
};

  const isLocalhostMode = config.domain === "localhost";

  function getWorkerBaseUrl(): string {
    if (isLocalhostMode) {
      return `http://localhost:${config.port}`;
    }
    return `http://api.${config.domain}:${config.port}`;
  }

  function getProjectBaseUrl(projectName: string): string {
    if (isLocalhostMode) {
      return `http://localhost:${config.port}/pages/${projectName}`;
    }
    return `http://${projectName}.${config.domain}:${config.port}`;
  }

// ============================================================================
// SERVICE INITIALIZATION
// ============================================================================

// LibSQL Client
const db = createClient({
    url: config.libsqlUrl,
    authToken: config.libsqlAuthToken,
});
const DATABASE_META_TABLE = "__v8box_databases";
const TABLE_META_TABLE = "__v8box_tables";

// Valkey (Redis) Client
const cache = await connect({
    hostname: new URL(config.valkeyUrl).hostname,
    port: parseInt(new URL(config.valkeyUrl).port || "6379"),
});

// S3 Client
const s3 = new S3Client({
    endpoint: config.s3Endpoint,
    region: config.s3Region,
    credentials: {
        accessKeyId: config.s3AccessKey,
        secretAccessKey: config.s3SecretKey,
    },
    forcePathStyle: true,
});

function getManagedBucketNames(): string[] {
    return [...new Set([
        config.s3DefaultBucket,
        config.s3ProjectsBucket,
        config.s3FunctionsBucket,
    ].filter(Boolean))];
}

async function bucketExists(bucketName: string): Promise<boolean> {
    try {
        await s3.send(new ListObjectsV2Command({ Bucket: bucketName, MaxKeys: 1 }));
        return true;
    } catch (error) {
        if (String(error).includes("NoSuchBucket")) {
            return false;
        }
        throw error;
    }
}

async function ensureS3Buckets(): Promise<void> {
    for (const bucketName of getManagedBucketNames()) {
        try {
            const exists = await bucketExists(bucketName);
            if (!exists) {
                await s3.send(new CreateBucketCommand({ Bucket: bucketName }));
                console.log(`✅ Created S3 bucket: ${bucketName}`);
            }
        } catch (error) {
            console.error(`⚠️ Failed to verify/create S3 bucket ${bucketName}:`, error);
        }
    }
}

await ensureS3Buckets();

async function ensureDatabaseMetadataTables(): Promise<void> {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS ${DATABASE_META_TABLE} (
      name TEXT PRIMARY KEY,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS ${TABLE_META_TABLE} (
      database_name TEXT NOT NULL,
      table_name TEXT NOT NULL,
      physical_name TEXT NOT NULL UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (database_name, table_name)
    )
  `);
}

await ensureDatabaseMetadataTables();

// Service Context for Workers
const services: ServiceContext = { db, cache, s3 };

// ============================================================================
// UTILITIES
// ============================================================================

// Validate filename/folder name (prevent path traversal)
function isValidName(name: string): boolean {
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

// Get subdomain from hostname
function getSubdomain(hostname: string): string {
  const hostWithoutPort = hostname.split(":")[0];
  const parts = hostWithoutPort.split(".");

  if (parts.length === 2 && parts[1] === "localhost") {
    return parts[0] === "localhost" ? "" : parts[0];
  }

    if (parts.length > 2) {
        return parts[0];
    }
    return "";
}

// Log worker execution
async function logExecution(funcName: string, log: ExecutionLog): Promise<void> {
    try {
        await ensureDir("./logs");
        const logPath = `./logs/${funcName}.log`;
        const logLine = `[${log.timestamp}] ${log.status.toUpperCase()} - Duration: ${log.duration}ms${log.error ? ` - Error: ${log.error}` : ""}\n`;
        await Deno.writeTextFile(logPath, logLine, { append: true });
    } catch (error) {
        console.error("Failed to write log:", error);
    }
}

// Read last N lines from log file
async function readLastLogs(funcName: string, lines = 50): Promise<string[]> {
    try {
        const logPath = `./logs/${funcName}.log`;
        if (!await exists(logPath)) {
            return [];
        }
        const content = await Deno.readTextFile(logPath);
        const allLines = content.split("\n").filter(line => line.trim());
        return allLines.slice(-lines);
    } catch {
        return [];
    }
}

// Get MIME type from extension
function getMimeType(ext: string): string {
    const mimeTypes: Record<string, string> = {
        ".html": "text/html",
        ".css": "text/css",
        ".js": "application/javascript",
        ".json": "application/json",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
        ".ico": "image/x-icon",
        ".txt": "text/plain",
        ".pdf": "application/pdf",
    };
    return mimeTypes[ext.toLowerCase()] || "application/octet-stream";
}

function isValidBucketName(name: string): boolean {
  return /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(name);
}

function isValidDatabaseName(name: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9_-]{1,62}$/.test(name);
}

function isValidIdentifier(name: string): boolean {
  return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name);
}

function quoteIdentifier(name: string): string {
  if (!isValidIdentifier(name)) {
    throw new Error(`Invalid SQL identifier: ${name}`);
  }
  return `"${name}"`;
}

function getDatabaseClient(): typeof db {
  return db;
}

function getPhysicalTableName(databaseName: string, tableName: string): string {
  return `v8db_${databaseName}__${tableName}`;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function resolveTableName(databaseName: string, tableName: string): Promise<string> {
  if (databaseName === "global") {
    return tableName;
  }

  const mapping = await db.execute({
    sql: `SELECT physical_name FROM ${TABLE_META_TABLE} WHERE database_name = ? AND table_name = ? LIMIT 1`,
    args: [databaseName, tableName],
  });

  if (mapping.rows.length === 0) {
    throw new Error("Table not found");
  }

  return String((mapping.rows[0] as Record<string, unknown>).physical_name || "");
}

async function rewriteQueryForDatabase(databaseName: string, query: string): Promise<string> {
  if (databaseName === "global") {
    return query;
  }

  const mappings = await db.execute({
    sql: `SELECT table_name, physical_name FROM ${TABLE_META_TABLE} WHERE database_name = ? ORDER BY LENGTH(table_name) DESC`,
    args: [databaseName],
  });

  let rewritten = query;
  for (const row of mappings.rows) {
    const mapping = row as Record<string, unknown>;
    const virtualName = String(mapping.table_name || "");
    const physicalName = String(mapping.physical_name || "");
    if (!virtualName || !physicalName) {
      continue;
    }

    const regex = new RegExp(`\\b${escapeRegex(virtualName)}\\b`, "g");
    rewritten = rewritten.replace(regex, physicalName);
  }

  return rewritten;
}

async function listDatabaseNames(): Promise<string[]> {
  const names = new Set<string>(["global"]);

  const rows = await db.execute(`SELECT name FROM ${DATABASE_META_TABLE} ORDER BY name`);
  for (const row of rows.rows) {
    const name = String((row as Record<string, unknown>).name || "");
    if (name) {
      names.add(name);
    }
  }

  return Array.from(names).sort();
}

async function createDatabase(databaseName: string): Promise<void> {
  if (!isValidDatabaseName(databaseName) || databaseName === "global") {
    throw new Error("Invalid database name");
  }

  const existsResult = await db.execute({
    sql: `SELECT 1 AS ok FROM ${DATABASE_META_TABLE} WHERE name = ? LIMIT 1`,
    args: [databaseName],
  });
  if (existsResult.rows.length > 0) {
    throw new Error("Database already exists");
  }

  await db.execute({
    sql: `INSERT INTO ${DATABASE_META_TABLE} (name) VALUES (?)`,
    args: [databaseName],
  });
}

async function ensureDatabaseExists(databaseName: string): Promise<void> {
  if (!isValidDatabaseName(databaseName) || databaseName === "global") {
    throw new Error("Invalid database name");
  }

  const existsResult = await db.execute({
    sql: `SELECT 1 AS ok FROM ${DATABASE_META_TABLE} WHERE name = ? LIMIT 1`,
    args: [databaseName],
  });

  if (existsResult.rows.length === 0) {
    throw new Error("Database not found");
  }
}

function sqlLiteral(value: unknown): string {
  if (value === null) {
    return "NULL";
  }
  if (typeof value === "number") {
    return `${value}`;
  }
  if (typeof value === "boolean") {
    return value ? "1" : "0";
  }
  return `'${String(value).replaceAll("'", "''")}'`;
}

async function parseRequestPayload(c: Context): Promise<Record<string, unknown>> {
  const contentType = c.req.header("content-type") || "";
  if (contentType.includes("application/json")) {
    const body = await c.req.json().catch(() => ({}));
    return (body && typeof body === "object") ? (body as Record<string, unknown>) : {};
  }

  const body = await c.req.parseBody();
  return Object.fromEntries(Object.entries(body));
}

function parseWhereInput(payload: Record<string, unknown>): { where: string; whereArgs: unknown[] } {
  const where = String(payload.where || "").trim();
  const whereArgsRaw = payload.whereArgs;
  const whereArgs = Array.isArray(whereArgsRaw) ? whereArgsRaw : [];

  if (!where) {
    throw new Error("where is required");
  }

  if (where.includes(";")) {
    throw new Error("Invalid where clause");
  }

  const invalidArg = whereArgs.find((arg) => {
    return arg !== null && ["string", "number", "boolean"].includes(typeof arg) === false;
  });

  if (invalidArg !== undefined) {
    throw new Error("whereArgs must contain only string, number, boolean, or null");
  }

  return { where, whereArgs };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

// Subdomain routing middleware
async function subdomainRouter(c: Context, next: Next) {
    const hostname = c.req.header("host") || "";
    const subdomain = getSubdomain(hostname);

    c.set("subdomain", subdomain);
    c.set("hostname", hostname);

    await next();
}

// Admin authentication middleware
async function adminAuth(c: Context, next: Next) {
    const sessionToken = getCookie(c, "admin_session");

    // Check if authenticated
    if (sessionToken === "authenticated") {
        await next();
        return;
    }

    // Check if login attempt
    if (c.req.method === "POST" && c.req.path === "/admin/login") {
        const body = await c.req.parseBody();
        if (body.password === config.adminPassword) {
            setCookie(c, "admin_session", "authenticated", {
                httpOnly: true,
                maxAge: 86400, // 24 hours
                path: "/",
            });
            return c.redirect("/admin");
        }
        return c.html(getLoginPage("Invalid password"), 401);
    }

    // Show login page
    if (!sessionToken) {
        return c.html(getLoginPage());
    }

    await next();
}

// ============================================================================
// HONO APP
// ============================================================================

const app = new Hono();

// Apply subdomain router globally
app.use("*", subdomainRouter);

// ============================================================================
// ADMIN ROUTES
// ============================================================================

app.get("/admin/login", (c) => c.html(getLoginPage()));
app.post("/admin/login", adminAuth, (c) => c.redirect("/admin"));

app.get("/admin/logout", (c) => {
    deleteCookie(c, "admin_session");
    return c.redirect("/admin/login");
});

// Admin Dashboard Home - Worker List
app.get("/admin", adminAuth, async (c) => {
    const subdomain = c.get("subdomain");
  if (!isLocalhostMode && subdomain !== "admin") {
        return c.text("Access admin via admin.domain.tld", 400);
    }

    const workers: { name: string; size: number }[] = [];
    try {
        await ensureDir("./functions");
        for await (const entry of Deno.readDir("./functions")) {
            if (entry.isFile && entry.name.endsWith(".ts")) {
                const stat = await Deno.stat(`./functions/${entry.name}`);
                workers.push({
                    name: entry.name,
                    size: stat.size,
                });
            }
        }
    } catch {
        // Directory doesn't exist or empty
    }

    return c.html(getDashboardPage(workers));
});

// Worker Detail - Code Editor + Logs
app.get("/admin/worker/:name", adminAuth, async (c) => {
    const name = c.req.param("name");

    if (!isValidName(name.replace(".ts", ""))) {
        return c.json<ApiResponse>({ success: false, error: "Invalid worker name" }, 400);
    }

    const filePath = `./functions/${name}`;

    let code = "";
    if (await exists(filePath)) {
        code = await Deno.readTextFile(filePath);
    } else {
        code = `// New worker: ${name}\nexport default async function handler({ db, cache, s3 }, params) {\n  return { message: "Hello from ${name}" };\n}\n`;
    }

    const logs = await readLastLogs(name.replace(".ts", ""));

    return c.html(getWorkerEditorPage(name, code, logs));
});

// Save Worker Code
app.post("/admin/worker/:name", adminAuth, async (c) => {
    const name = c.req.param("name");

    if (!isValidName(name.replace(".ts", ""))) {
        return c.json<ApiResponse>({ success: false, error: "Invalid worker name" }, 400);
    }

    const body = await c.req.parseBody();
    const code = body.code as string;

    await ensureDir("./functions");
    await Deno.writeTextFile(`./functions/${name}`, code);

    return c.json<ApiResponse>({ success: true });
});

// Delete Worker
app.delete("/admin/worker/:name", adminAuth, async (c) => {
    const name = c.req.param("name");

    if (!isValidName(name.replace(".ts", ""))) {
        return c.json<ApiResponse>({ success: false, error: "Invalid worker name" }, 400);
    }

    try {
        await Deno.remove(`./functions/${name}`);
        return c.json<ApiResponse>({ success: true });
    } catch (error) {
        return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
    }
});

// Pages Manager
app.get("/admin/pages", adminAuth, async (c) => {
    const projects: PageProject[] = [];

    try {
        await ensureDir("./storage/pages");
        for await (const entry of Deno.readDir("./storage/pages")) {
            if (entry.isDirectory) {
                let fileCount = 0;
                for await (const _ of Deno.readDir(`./storage/pages/${entry.name}`)) {
                    fileCount++;
                }
                projects.push({
                    name: entry.name,
                    path: `./storage/pages/${entry.name}`,
                    files: fileCount,
                });
            }
        }
    } catch {
        // Directory doesn't exist
    }

    return c.html(getPagesManagerPage(projects));
});

// Upload & Auto-Unzip Pages
app.post("/admin/pages/upload", adminAuth, async (c) => {
    const body = await c.req.parseBody();
    const file = body.file as File;
    const projectName = (body.project_name as string) || file.name.replace(".zip", "");

    if (!isValidName(projectName)) {
        return c.json<ApiResponse>({ success: false, error: "Invalid project name" }, 400);
    }

    try {
        // Read ZIP file
        const arrayBuffer = await file.arrayBuffer();
        const zip = new JSZip();
        await zip.loadAsync(arrayBuffer);

        // Extract to project folder
        const projectPath = `./storage/pages/${projectName}`;
        await ensureDir(projectPath);

        // Extract all files
        for (const [filename, zipEntry] of Object.entries(zip.files)) {
            if (!zipEntry.dir) {
                const content = await zipEntry.async("uint8array");
                const filePath = join(projectPath, filename);
                await ensureDir(join(projectPath, ...filename.split("/").slice(0, -1)));
                await Deno.writeFile(filePath, content);
            }
        }

        return c.json<ApiResponse>({ success: true, data: { projectName } });
    } catch (error) {
        return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
    }
});

// Delete Pages Project
app.delete("/admin/pages/:name", adminAuth, async (c) => {
    const name = c.req.param("name");

    if (!isValidName(name)) {
        return c.json<ApiResponse>({ success: false, error: "Invalid project name" }, 400);
    }

    try {
        await Deno.remove(`./storage/pages/${name}`, { recursive: true });
        return c.json<ApiResponse>({ success: true });
    } catch (error) {
        return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
    }
});

// Database Explorer
app.get("/admin/database", adminAuth, (c) => {
    return c.html(getDatabaseExplorerPage());
});

app.get("/admin/database/databases", adminAuth, async (c) => {
  const databases = await listDatabaseNames();
  return c.json<ApiResponse>({ success: true, data: { databases } });
});

app.post("/admin/database/databases", adminAuth, async (c) => {
  const payload = await parseRequestPayload(c);
  const databaseName = String(payload.name || "").trim();

  if (!isValidDatabaseName(databaseName) || databaseName === "global") {
    return c.json<ApiResponse>({ success: false, error: "Invalid database name" }, 400);
  }

  try {
    await createDatabase(databaseName);
    return c.json<ApiResponse>({ success: true, data: { database: databaseName } });
  } catch (error) {
    return c.json<ApiResponse>({ success: false, error: String(error) }, 400);
  }
});

app.delete("/admin/database/databases/:database", adminAuth, async (c) => {
  const databaseName = c.req.param("database");

  if (!isValidDatabaseName(databaseName) || databaseName === "global") {
    return c.json<ApiResponse>({ success: false, error: "Invalid database name" }, 400);
  }

  try {
    await ensureDatabaseExists(databaseName);

    const mappingRows = await db.execute({
      sql: `SELECT physical_name FROM ${TABLE_META_TABLE} WHERE database_name = ?`,
      args: [databaseName],
    });

    for (const row of mappingRows.rows) {
      const physicalName = String((row as Record<string, unknown>).physical_name || "");
      if (physicalName) {
        await db.execute(`DROP TABLE IF EXISTS ${quoteIdentifier(physicalName)}`);
      }
    }

    await db.execute({
      sql: `DELETE FROM ${TABLE_META_TABLE} WHERE database_name = ?`,
      args: [databaseName],
    });

    await db.execute({
      sql: `DELETE FROM ${DATABASE_META_TABLE} WHERE name = ?`,
      args: [databaseName],
    });

    return c.json<ApiResponse>({ success: true, data: { database: databaseName } });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 500;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.get("/admin/database/databases/:database/tables", adminAuth, async (c) => {
  const databaseName = c.req.param("database");

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    let tables: string[] = [];
    if (databaseName === "global") {
      const result = await db.execute(
        `SELECT name FROM sqlite_master
         WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%'
           AND name NOT LIKE 'v8db_%'
           AND name NOT IN ('${DATABASE_META_TABLE}', '${TABLE_META_TABLE}')
         ORDER BY name`
      );

      tables = result.rows
        .map((row) => String((row as Record<string, unknown>).name || ""))
        .filter(Boolean);
    } else {
      const result = await db.execute({
        sql: `SELECT table_name FROM ${TABLE_META_TABLE} WHERE database_name = ? ORDER BY table_name`,
        args: [databaseName],
      });

      tables = result.rows
        .map((row) => String((row as Record<string, unknown>).table_name || ""))
        .filter(Boolean);
    }

    return c.json<ApiResponse>({ success: true, data: { database: databaseName, tables } });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.post("/admin/database/databases/:database/tables", adminAuth, async (c) => {
  const databaseName = c.req.param("database");

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const payload = await parseRequestPayload(c);
    const tableName = String(payload.tableName || "").trim();
    const columns = Array.isArray(payload.columns) ? payload.columns as Array<Record<string, unknown>> : [];

    if (!isValidIdentifier(tableName)) {
      return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
    }

    if (columns.length === 0) {
      return c.json<ApiResponse>({ success: false, error: "Columns are required" }, 400);
    }

    const definitions = columns.map((column) => {
      const columnName = String(column.name || "").trim();
      const rawType = String(column.type || "TEXT").trim().toUpperCase();
      const nullable = Boolean(column.nullable ?? true);
      const primaryKey = Boolean(column.primaryKey ?? false);
      const unique = Boolean(column.unique ?? false);
      const autoIncrement = Boolean(column.autoIncrement ?? false);
      const hasDefault = Object.prototype.hasOwnProperty.call(column, "default");
      const defaultValue = column.default;

      if (!isValidIdentifier(columnName)) {
        throw new Error(`Invalid column name: ${columnName}`);
      }

      if (!/^[A-Z][A-Z0-9_()]*$/.test(rawType)) {
        throw new Error(`Invalid column type: ${rawType}`);
      }

      let definition = `${quoteIdentifier(columnName)} ${rawType}`;

      if (primaryKey) {
        definition += " PRIMARY KEY";
      }

      if (autoIncrement) {
        definition += " AUTOINCREMENT";
      }

      if (!nullable) {
        definition += " NOT NULL";
      }

      if (unique) {
        definition += " UNIQUE";
      }

      if (hasDefault) {
        definition += ` DEFAULT ${sqlLiteral(defaultValue)}`;
      }

      return definition;
    });

    let targetTableName = tableName;
    if (databaseName !== "global") {
      const existing = await db.execute({
        sql: `SELECT 1 AS ok FROM ${TABLE_META_TABLE} WHERE database_name = ? AND table_name = ? LIMIT 1`,
        args: [databaseName, tableName],
      });
      if (existing.rows.length > 0) {
        return c.json<ApiResponse>({ success: false, error: "Table already exists" }, 400);
      }

      targetTableName = getPhysicalTableName(databaseName, tableName);
    }

    const sql = `CREATE TABLE IF NOT EXISTS ${quoteIdentifier(targetTableName)} (${definitions.join(", ")})`;
    await db.execute(sql);

    if (databaseName !== "global") {
      await db.execute({
        sql: `INSERT INTO ${TABLE_META_TABLE} (database_name, table_name, physical_name) VALUES (?, ?, ?)`,
        args: [databaseName, tableName, targetTableName],
      });
    }

    return c.json<ApiResponse>({ success: true, data: { database: databaseName, table: tableName } });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.delete("/admin/database/databases/:database/tables/:table", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);
    await db.execute(`DROP TABLE IF EXISTS ${quoteIdentifier(targetTableName)}`);

    if (databaseName !== "global") {
      await db.execute({
        sql: `DELETE FROM ${TABLE_META_TABLE} WHERE database_name = ? AND table_name = ?`,
        args: [databaseName, tableName],
      });
    }

    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.post("/admin/database/databases/:database/tables/:table/rows", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const payload = await parseRequestPayload(c);
    const data = payload.data as Record<string, unknown> | undefined;

    if (!data || typeof data !== "object") {
      return c.json<ApiResponse>({ success: false, error: "Body data is required" }, 400);
    }

    const entries = Object.entries(data);
    const targetDb = getDatabaseClient();
    let result;

    if (entries.length === 0) {
      result = await targetDb.execute(`INSERT INTO ${quoteIdentifier(targetTableName)} DEFAULT VALUES`);
    } else {
      const invalidColumn = entries.find(([column]) => !isValidIdentifier(column));
      if (invalidColumn) {
        return c.json<ApiResponse>({ success: false, error: `Invalid column name: ${invalidColumn[0]}` }, 400);
      }

      const columnsSql = entries.map(([column]) => quoteIdentifier(column)).join(", ");
      const valuesSql = entries.map(() => "?").join(", ");
      const args = entries.map(([, value]) => value);

      result = await targetDb.execute({
        sql: `INSERT INTO ${quoteIdentifier(targetTableName)} (${columnsSql}) VALUES (${valuesSql})`,
        args,
      });
    }

    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
        lastInsertRowid: result.lastInsertRowid !== undefined && result.lastInsertRowid !== null
          ? String(result.lastInsertRowid)
          : null,
        rowsAffected: result.rowsAffected,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.get("/admin/database/databases/:database/tables/:table/rows", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  const limitRaw = Number(c.req.query("limit") || "100");
  const offsetRaw = Number(c.req.query("offset") || "0");
  const orderBy = c.req.query("orderBy");
  const orderRaw = String(c.req.query("order") || "ASC").toUpperCase();

  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 100;
  const offset = Number.isFinite(offsetRaw) ? Math.max(offsetRaw, 0) : 0;
  const order = orderRaw === "DESC" ? "DESC" : "ASC";

  if (orderBy && !isValidIdentifier(orderBy)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid orderBy column" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const targetDb = getDatabaseClient();
    const orderClause = orderBy ? ` ORDER BY ${quoteIdentifier(orderBy)} ${order}` : "";
    const sql = `SELECT * FROM ${quoteIdentifier(targetTableName)}${orderClause} LIMIT ? OFFSET ?`;

    const result = await targetDb.execute({ sql, args: [limit, offset] });
    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
        rows: result.rows,
        columns: result.columns,
        rowCount: result.rows.length,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.get("/admin/database/databases/:database/tables/:table/rows/:id", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");
  const id = c.req.param("id");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const targetDb = getDatabaseClient();
    const result = await targetDb.execute({
      sql: `SELECT * FROM ${quoteIdentifier(targetTableName)} WHERE id = ? LIMIT 1`,
      args: [id],
    });

    if (result.rows.length === 0) {
      return c.json<ApiResponse>({ success: false, error: "Row not found" }, 404);
    }

    return c.json<ApiResponse>({ success: true, data: { row: result.rows[0] } });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.post("/admin/database/databases/:database/tables/:table/rows/search", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const payload = await parseRequestPayload(c);
    const { where, whereArgs } = parseWhereInput(payload);

    const limitRaw = Number(payload.limit ?? 100);
    const offsetRaw = Number(payload.offset ?? 0);
    const orderBy = payload.orderBy ? String(payload.orderBy).trim() : "";
    const orderRaw = String(payload.order || "ASC").toUpperCase();

    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 100;
    const offset = Number.isFinite(offsetRaw) ? Math.max(offsetRaw, 0) : 0;
    const order = orderRaw === "DESC" ? "DESC" : "ASC";

    if (orderBy && !isValidIdentifier(orderBy)) {
      return c.json<ApiResponse>({ success: false, error: "Invalid orderBy column" }, 400);
    }

    const orderClause = orderBy ? ` ORDER BY ${quoteIdentifier(orderBy)} ${order}` : "";
    const sql = `SELECT * FROM ${quoteIdentifier(targetTableName)} WHERE ${where}${orderClause} LIMIT ? OFFSET ?`;

    const targetDb = getDatabaseClient();
    const result = await targetDb.execute({ sql, args: [...whereArgs, limit, offset] });

    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
        rows: result.rows,
        columns: result.columns,
        rowCount: result.rows.length,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.put("/admin/database/databases/:database/tables/:table/rows", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const payload = await parseRequestPayload(c);
    const data = payload.data as Record<string, unknown> | undefined;
    if (!data || typeof data !== "object") {
      return c.json<ApiResponse>({ success: false, error: "Body data is required" }, 400);
    }

    const entries = Object.entries(data);
    if (entries.length === 0) {
      return c.json<ApiResponse>({ success: false, error: "No columns to update" }, 400);
    }

    const invalidColumn = entries.find(([column]) => !isValidIdentifier(column));
    if (invalidColumn) {
      return c.json<ApiResponse>({ success: false, error: `Invalid column name: ${invalidColumn[0]}` }, 400);
    }

    const { where, whereArgs } = parseWhereInput(payload);
    const setClause = entries.map(([column]) => `${quoteIdentifier(column)} = ?`).join(", ");
    const args = [...entries.map(([, value]) => value), ...whereArgs];

    const targetDb = getDatabaseClient();
    const result = await targetDb.execute({
      sql: `UPDATE ${quoteIdentifier(targetTableName)} SET ${setClause} WHERE ${where}`,
      args,
    });

    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
        rowsAffected: result.rowsAffected,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.delete("/admin/database/databases/:database/tables/:table/rows", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const payload = await parseRequestPayload(c);
    const { where, whereArgs } = parseWhereInput(payload);

    const targetDb = getDatabaseClient();
    const result = await targetDb.execute({
      sql: `DELETE FROM ${quoteIdentifier(targetTableName)} WHERE ${where}`,
      args: whereArgs,
    });

    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
        rowsAffected: result.rowsAffected,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.put("/admin/database/databases/:database/tables/:table/rows/:id", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");
  const id = c.req.param("id");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const payload = await parseRequestPayload(c);
    const data = payload.data as Record<string, unknown> | undefined;
    if (!data || typeof data !== "object") {
      return c.json<ApiResponse>({ success: false, error: "Body data is required" }, 400);
    }

    const entries = Object.entries(data);
    if (entries.length === 0) {
      return c.json<ApiResponse>({ success: false, error: "No columns to update" }, 400);
    }

    const invalidColumn = entries.find(([column]) => !isValidIdentifier(column));
    if (invalidColumn) {
      return c.json<ApiResponse>({ success: false, error: `Invalid column name: ${invalidColumn[0]}` }, 400);
    }

    const setClause = entries.map(([column]) => `${quoteIdentifier(column)} = ?`).join(", ");
    const args = [...entries.map(([, value]) => value), id];

    const targetDb = getDatabaseClient();
    const result = await targetDb.execute({
      sql: `UPDATE ${quoteIdentifier(targetTableName)} SET ${setClause} WHERE id = ?`,
      args,
    });

    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
        id,
        rowsAffected: result.rowsAffected,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

app.delete("/admin/database/databases/:database/tables/:table/rows/:id", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const tableName = c.req.param("table");
  const id = c.req.param("id");

  if (!isValidIdentifier(tableName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid table name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetTableName = await resolveTableName(databaseName, tableName);

    const targetDb = getDatabaseClient();
    const result = await targetDb.execute({
      sql: `DELETE FROM ${quoteIdentifier(targetTableName)} WHERE id = ?`,
      args: [id],
    });

    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        table: tableName,
        id,
        rowsAffected: result.rowsAffected,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 400;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

// Execute SQL Query (Global or specific database)
app.post("/admin/database/query/global", adminAuth, async (c) => {
  const payload = await parseRequestPayload(c);
  const query = String(payload.query || "").trim();

  if (!query) {
    return c.json<ApiResponse>({ success: false, error: "Query is required" }, 400);
  }

  try {
    const result = await db.execute(query);
    return c.json<ApiResponse>({
      success: true,
      data: {
        database: "global",
        rows: result.rows,
        columns: result.columns,
        rowsAffected: result.rowsAffected,
      },
    });
  } catch (error) {
    return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
  }
});

app.post("/admin/database/query/:database", adminAuth, async (c) => {
  const databaseName = c.req.param("database");
  const payload = await parseRequestPayload(c);
  const query = String(payload.query || "").trim();

  if (!query) {
    return c.json<ApiResponse>({ success: false, error: "Query is required" }, 400);
  }

  if (databaseName !== "global" && !isValidDatabaseName(databaseName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid database name" }, 400);
  }

  try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetDb = getDatabaseClient();
    const rewrittenQuery = await rewriteQueryForDatabase(databaseName, query);
    const result = await targetDb.execute(rewrittenQuery);
    return c.json<ApiResponse>({
      success: true,
      data: {
        database: databaseName,
        rows: result.rows,
        columns: result.columns,
        rowsAffected: result.rowsAffected,
      },
    });
  } catch (error) {
    const status = String(error).includes("not found") ? 404 : 500;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
  }
});

// Execute SQL Query
app.post("/admin/database/query", adminAuth, async (c) => {
  const payload = await parseRequestPayload(c);
  const query = String(payload.query || "").trim();
  const databaseName = String(payload.database || "global").trim() || "global";

  if (!query) {
    return c.json<ApiResponse>({ success: false, error: "Query is required" }, 400);
  }

  if (databaseName !== "global" && !isValidDatabaseName(databaseName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid database name" }, 400);
  }

    try {
    if (databaseName !== "global") {
      await ensureDatabaseExists(databaseName);
    }

    const targetDb = getDatabaseClient();
    const rewrittenQuery = await rewriteQueryForDatabase(databaseName, query);
    const result = await targetDb.execute(rewrittenQuery);
        return c.json<ApiResponse>({
            success: true,
            data: {
        database: databaseName,
                rows: result.rows,
                columns: result.columns,
                rowsAffected: result.rowsAffected,
            },
        });
    } catch (error) {
    const status = String(error).includes("not found") ? 404 : 500;
    return c.json<ApiResponse>({ success: false, error: String(error) }, status);
    }
});

async function listAllBuckets(): Promise<S3Bucket[]> {
  const response = await s3.send(new ListBucketsCommand({}));
  return (response.Buckets || []).map((bucket) => ({
    name: bucket.Name || "",
    createdAt: bucket.CreationDate,
  })).filter((bucket) => bucket.name);
}

async function deleteAllObjectsInBucket(bucketName: string): Promise<void> {
  let continuationToken: string | undefined;
  do {
    const response = await s3.send(new ListObjectsV2Command({
      Bucket: bucketName,
      ContinuationToken: continuationToken,
    }));

    for (const object of response.Contents || []) {
      if (!object.Key) {
        continue;
      }
      await s3.send(new DeleteObjectCommand({
        Bucket: bucketName,
        Key: object.Key,
      }));
    }

    continuationToken = response.NextContinuationToken;
  } while (continuationToken);
}

async function renameBucket(oldName: string, newName: string): Promise<void> {
  await s3.send(new CreateBucketCommand({ Bucket: newName }));

  let continuationToken: string | undefined;
  do {
    const response = await s3.send(new ListObjectsV2Command({
      Bucket: oldName,
      ContinuationToken: continuationToken,
    }));

    for (const object of response.Contents || []) {
      if (!object.Key) {
        continue;
      }

      const encodedKey = encodeURIComponent(object.Key).replaceAll("%2F", "/");
      await s3.send(new CopyObjectCommand({
        Bucket: newName,
        Key: object.Key,
        CopySource: `${oldName}/${encodedKey}`,
      }));

      await s3.send(new DeleteObjectCommand({
        Bucket: oldName,
        Key: object.Key,
      }));
    }

    continuationToken = response.NextContinuationToken;
  } while (continuationToken);

  await s3.send(new DeleteBucketCommand({ Bucket: oldName }));
}

// S3 Browser
app.get("/admin/s3", adminAuth, async (c) => {
  let selectedBucket = c.req.query("bucket") || config.s3DefaultBucket;

  try {
    const buckets = await listAllBuckets();
    if (buckets.length > 0 && !buckets.some((bucket) => bucket.name === selectedBucket)) {
      selectedBucket = buckets[0].name;
    }

    let objects: S3Object[] = [];
    if (selectedBucket) {
      const response = await s3.send(new ListObjectsV2Command({ Bucket: selectedBucket }));
      objects = (response.Contents || []).map((obj) => ({
        key: obj.Key || "",
        size: obj.Size || 0,
        lastModified: obj.LastModified,
      }));
    }

    return c.html(getS3BrowserPage(buckets, selectedBucket, objects));
  } catch (error) {
    const buckets = await listAllBuckets().catch(() => []);
    return c.html(getS3BrowserPage(buckets, selectedBucket, [], String(error)));
  }
});

// Create S3 Bucket
app.post("/admin/s3/buckets", adminAuth, async (c) => {
  const body = await c.req.parseBody();
  const bucketName = String(body.bucketName || "").trim().toLowerCase();

  if (!isValidBucketName(bucketName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid bucket name" }, 400);
  }

  try {
    await s3.send(new CreateBucketCommand({ Bucket: bucketName }));
    return c.json<ApiResponse>({ success: true, data: { bucketName } });
  } catch (error) {
    return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
  }
});

// Rename S3 Bucket
app.put("/admin/s3/buckets/:name", adminAuth, async (c) => {
  const oldName = c.req.param("name");
  const body = await c.req.parseBody();
  const newName = String(body.newName || "").trim().toLowerCase();

  if (!isValidBucketName(oldName) || !isValidBucketName(newName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid bucket name" }, 400);
  }

  if (oldName === newName) {
    return c.json<ApiResponse>({ success: true, data: { bucketName: oldName } });
  }

  try {
    await renameBucket(oldName, newName);
    return c.json<ApiResponse>({ success: true, data: { bucketName: newName } });
  } catch (error) {
    return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
  }
});

// Delete S3 Bucket
app.delete("/admin/s3/buckets/:name", adminAuth, async (c) => {
  const bucketName = c.req.param("name");

  if (!isValidBucketName(bucketName)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid bucket name" }, 400);
  }

  try {
    await deleteAllObjectsInBucket(bucketName);
    await s3.send(new DeleteBucketCommand({ Bucket: bucketName }));
    return c.json<ApiResponse>({ success: true });
  } catch (error) {
    return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
  }
});

// Delete S3 Object
app.delete("/admin/s3/object/:key", adminAuth, async (c) => {
  const key = c.req.param("key");
  const bucket = (c.req.query("bucket") || config.s3DefaultBucket).trim();

  if (!isValidBucketName(bucket)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid bucket name" }, 400);
  }

  try {
    await s3.send(new DeleteObjectCommand({
      Bucket: bucket,
      Key: key,
    }));
    return c.json<ApiResponse>({ success: true });
  } catch (error) {
    return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
  }
});

// Upload S3 Object
app.post("/admin/s3/object", adminAuth, async (c) => {
  const body = await c.req.parseBody();
  const bucket = String(body.bucket || config.s3DefaultBucket).trim();
  const file = body.file as File | undefined;
  const providedKey = String(body.key || "").trim();

  if (!isValidBucketName(bucket)) {
    return c.json<ApiResponse>({ success: false, error: "Invalid bucket name" }, 400);
  }

  if (!file) {
    return c.json<ApiResponse>({ success: false, error: "File is required" }, 400);
  }

  const key = providedKey || file.name;
  if (!key) {
    return c.json<ApiResponse>({ success: false, error: "Object key is required" }, 400);
  }

  try {
    await s3.send(new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: new Uint8Array(await file.arrayBuffer()),
      ContentType: file.type || "application/octet-stream",
    }));

    return c.json<ApiResponse>({
      success: true,
      data: {
        bucket,
        key,
        size: file.size,
      },
    });
  } catch (error) {
    return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
  }
});

// ============================================================================
// GIT SYNC WEBHOOK
// ============================================================================

app.post("/webhook/git", async (c) => {
    try {
        const payload = await c.req.json();
        const repoUrl = payload.repository?.clone_url || payload.repository?.url;

        if (!repoUrl) {
            return c.json<ApiResponse>({ success: false, error: "No repository URL found" }, 400);
        }

        // Execute git pull
        const process = new Deno.Command("git", {
            args: ["pull"],
            cwd: "./",
        });

        const { code, stdout, stderr } = await process.output();

        const output = new TextDecoder().decode(stdout);
        const error = new TextDecoder().decode(stderr);

        return c.json<ApiResponse>({
            success: code === 0,
            data: { output, error, repoUrl },
        });
    } catch (error) {
        return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
    }
});

// ============================================================================
// WORKER EXECUTION (api.domain.tld/run/:func)
// ============================================================================

app.all("/run/:func", async (c) => {
    const subdomain = c.get("subdomain");

  if (!isLocalhostMode && subdomain !== "api") {
        return c.json<ApiResponse>({ success: false, error: "Access workers via api.domain.tld" }, 400);
    }

    const funcName = c.req.param("func");

    if (!isValidName(funcName)) {
        return c.json<ApiResponse>({ success: false, error: "Invalid function name" }, 400);
    }

    const startTime = Date.now();

    try {
        // Dynamic import with cache-busting
        const timestamp = Date.now();
        const workerPath = `./functions/${funcName}.ts`;

        if (!await exists(workerPath)) {
            return c.json<ApiResponse>({ success: false, error: "Worker not found" }, 404);
        }

        // Import with cache busting
        const module = await import(`${workerPath}?t=${timestamp}`);
        const handler = module.default;

        if (typeof handler !== "function") {
            throw new Error("Worker must export a default function");
        }

        // Get request params
        const params = c.req.method === "GET"
            ? Object.fromEntries(new URL(c.req.url).searchParams)
            : await c.req.json().catch(() => ({}));

        // Execute worker with service injection
        const result = await handler(services, params);

        const duration = Date.now() - startTime;

        // Log execution
        await logExecution(funcName, {
            timestamp: new Date().toISOString(),
            status: "success",
            duration,
        });

        return c.json<ApiResponse>({
            success: true,
            data: result,
            timestamp: Date.now(),
        });
    } catch (error) {
        const duration = Date.now() - startTime;
        const errorMessage = String(error);

        // Log error
        await logExecution(funcName, {
            timestamp: new Date().toISOString(),
            status: "error",
            duration,
            error: errorMessage,
        });

        return c.json<ApiResponse>({
            success: false,
            error: errorMessage,
            timestamp: Date.now(),
        }, 500);
    }
});

// ============================================================================
// PAGES HOSTING (*.domain.tld)
// ============================================================================

async function serveProjectFile(c: Context, projectName: string, requestPath: string) {
  if (!isValidName(projectName)) {
    return c.text("Invalid project name", 400);
  }

  const normalizedPath = requestPath === "/" ? "/index.html" : requestPath;
  const filePath = join("./storage/pages", projectName, normalizedPath);

  try {
    if (!await exists(filePath)) {
      const indexPath = join(filePath, "index.html");
      if (await exists(indexPath)) {
        const content = await Deno.readFile(indexPath);
        return c.body(content, 200, { "Content-Type": "text/html" });
      }
      return c.notFound();
    }

    const stat = await Deno.stat(filePath);
    if (stat.isDirectory) {
      const indexPath = join(filePath, "index.html");
      if (await exists(indexPath)) {
        const content = await Deno.readFile(indexPath);
        return c.body(content, 200, { "Content-Type": "text/html" });
      }
      return c.text("Directory listing not allowed", 403);
    }

    const content = await Deno.readFile(filePath);
    const ext = extname(filePath);
    const mimeType = getMimeType(ext);

    return c.body(content, 200, { "Content-Type": mimeType });
  } catch (error) {
    console.error("Error serving file:", error);
    return c.notFound();
  }
}

app.get("/pages/:project", async (c) => {
  if (!isLocalhostMode) {
    return c.notFound();
  }

  const projectName = c.req.param("project");
  return await serveProjectFile(c, projectName, "/");
});

app.get("/pages/:project/*", async (c) => {
  if (!isLocalhostMode) {
    return c.notFound();
  }

  const projectName = c.req.param("project");
  const wildcardPath = c.req.param("*") || "";
  const requestPath = `/${wildcardPath}`;
  return await serveProjectFile(c, projectName, requestPath);
});

app.get("/*", async (c) => {
  if (isLocalhostMode) {
    return c.notFound();
  }

    const subdomain = c.get("subdomain");

    // Skip admin and api subdomains
    if (subdomain === "admin" || subdomain === "api" || !subdomain) {
        return c.notFound();
    }

    return await serveProjectFile(c, subdomain, c.req.path);
});

// ============================================================================
// HTML TEMPLATES
// ============================================================================

function getLoginPage(error?: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V8Box - Admin Login</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 min-h-screen flex items-center justify-center">
  <div class="bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl p-8 w-96">
    <h1 class="text-3xl font-bold text-white mb-6 text-center">V8Box Admin</h1>
    ${error ? `<div class="bg-red-500/20 border border-red-500 text-red-200 px-4 py-3 rounded mb-4">${error}</div>` : ""}
    <form method="POST" action="/admin/login">
      <input type="password" name="password" placeholder="Admin Password" 
        class="w-full px-4 py-3 bg-white/20 text-white placeholder-white/60 rounded-lg mb-4 focus:outline-none focus:ring-2 focus:ring-purple-500">
      <button type="submit" class="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-3 rounded-lg transition">
        Login
      </button>
    </form>
  </div>
</body>
</html>`;
}

function getDashboardPage(workers: { name: string; size: number }[]): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V8Box - Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
    <div class="flex justify-between items-center">
      <h1 class="text-2xl font-bold text-purple-400">V8Box Dashboard</h1>
      <div class="space-x-4">
        <a href="/admin" class="text-purple-400 hover:text-purple-300">Workers</a>
        <a href="/admin/pages" class="text-gray-400 hover:text-white">Pages</a>
        <a href="/admin/database" class="text-gray-400 hover:text-white">Database</a>
        <a href="/admin/s3" class="text-gray-400 hover:text-white">S3 Browser</a>
        <a href="/admin/logout" class="text-red-400 hover:text-red-300">Logout</a>
      </div>
    </div>
  </nav>
  
  <div class="container mx-auto px-6 py-8">
    <div class="flex justify-between items-center mb-6">
      <h2 class="text-3xl font-bold">Workers</h2>
      <a href="/admin/worker/new.ts" class="bg-purple-600 hover:bg-purple-700 px-6 py-2 rounded-lg font-semibold">+ New Worker</a>
    </div>
    
    <div class="bg-gray-800 rounded-lg overflow-hidden">
      <table class="w-full">
        <thead class="bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left">Name</th>
            <th class="px-6 py-3 text-left">Size</th>
            <th class="px-6 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${workers.length === 0 ?
            '<tr><td colspan="3" class="px-6 py-8 text-center text-gray-400">No workers found. Create your first worker!</td></tr>' :
            workers.map(w => `
              <tr class="border-t border-gray-700 hover:bg-gray-700/50">
                <td class="px-6 py-4 font-mono">${w.name}</td>
                <td class="px-6 py-4">${(w.size / 1024).toFixed(2)} KB</td>
                <td class="px-6 py-4 text-right space-x-2">
                  <a href="/admin/worker/${w.name}" class="text-blue-400 hover:text-blue-300">Edit</a>
                  <button onclick="deleteWorker('${w.name}')" class="text-red-400 hover:text-red-300">Delete</button>
                </td>
              </tr>
            `).join("")}
        </tbody>
      </table>
    </div>
  </div>
  
  <script>
    async function deleteWorker(name) {
      if (!confirm('Delete worker: ' + name + '?')) return;
      try {
        const res = await fetch('/admin/worker/' + name, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
          location.reload();
        } else {
          alert('Error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  </script>
</body>
</html>`;
}

function getWorkerEditorPage(name: string, code: string, logs: string[]): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V8Box - Edit ${name}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
    <div class="flex justify-between items-center">
      <h1 class="text-2xl font-bold text-purple-400">Edit Worker: ${name}</h1>
      <div class="space-x-4">
        <a href="/admin" class="text-gray-400 hover:text-white">← Back</a>
        <a href="/admin/logout" class="text-red-400 hover:text-red-300">Logout</a>
      </div>
    </div>
  </nav>
  
  <div class="container mx-auto px-6 py-8">
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Code Editor -->
      <div class="lg:col-span-2">
        <div class="bg-gray-800 rounded-lg p-6">
          <h3 class="text-xl font-bold mb-4">Code Editor</h3>
          <textarea id="code" rows="25" class="w-full bg-gray-900 text-green-400 font-mono text-sm p-4 rounded border border-gray-700 focus:outline-none focus:ring-2 focus:ring-purple-500">${code.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</textarea>
          <div class="mt-4 flex gap-4">
            <button onclick="saveCode()" class="bg-purple-600 hover:bg-purple-700 px-6 py-2 rounded-lg font-semibold">Save</button>
            <button onclick="testWorker()" class="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded-lg font-semibold">Test Run</button>
          </div>
          <div id="message" class="mt-4"></div>
        </div>
      </div>
      
      <!-- Logs -->
      <div class="lg:col-span-1">
        <div class="bg-gray-800 rounded-lg p-6">
          <h3 class="text-xl font-bold mb-4">Execution Logs (Last 50)</h3>
          <div class="bg-gray-900 text-xs font-mono p-4 rounded border border-gray-700 h-96 overflow-y-auto">
            ${logs.length === 0 ?
            '<div class="text-gray-500">No logs yet</div>' :
            logs.map(log => `<div class="mb-1">${log.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>`).join("")}
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    async function saveCode() {
      const code = document.getElementById('code').value;
      const msg = document.getElementById('message');
      try {
        const res = await fetch('/admin/worker/${name}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'code=' + encodeURIComponent(code)
        });
        const data = await res.json();
        if (data.success) {
          msg.innerHTML = '<div class="bg-green-600 text-white px-4 py-2 rounded">Saved successfully!</div>';
          setTimeout(() => msg.innerHTML = '', 3000);
        } else {
          msg.innerHTML = '<div class="bg-red-600 text-white px-4 py-2 rounded">Error: ' + data.error + '</div>';
        }
      } catch (err) {
        msg.innerHTML = '<div class="bg-red-600 text-white px-4 py-2 rounded">Error: ' + err.message + '</div>';
      }
    }
    
    async function testWorker() {
      const funcName = '${name}'.replace('.ts', '');
      const workerUrl = ${isLocalhostMode ? "window.location.origin + '/run/' + funcName" : "'http://api." + config.domain + ":" + config.port + "/run/' + funcName"};
      window.open(workerUrl, '_blank');
    }
  </script>
</body>
</html>`;
}

function getPagesManagerPage(projects: PageProject[]): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V8Box - Pages Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
    <div class="flex justify-between items-center">
      <h1 class="text-2xl font-bold text-purple-400">Pages Manager</h1>
      <div class="space-x-4">
        <a href="/admin" class="text-gray-400 hover:text-white">Workers</a>
        <a href="/admin/pages" class="text-purple-400 hover:text-purple-300">Pages</a>
        <a href="/admin/database" class="text-gray-400 hover:text-white">Database</a>
        <a href="/admin/s3" class="text-gray-400 hover:text-white">S3 Browser</a>
        <a href="/admin/logout" class="text-red-400 hover:text-red-300">Logout</a>
      </div>
    </div>
  </nav>
  
  <div class="container mx-auto px-6 py-8">
    <!-- Upload Form -->
    <div class="bg-gray-800 rounded-lg p-6 mb-6">
      <h2 class="text-2xl font-bold mb-4">Upload New Project</h2>
      <form onsubmit="uploadProject(event)" class="space-y-4">
        <div>
          <label class="block mb-2">Project Name (subdomain)</label>
          <input type="text" id="projectName" placeholder="mysite" pattern="[a-zA-Z0-9_-]+" 
            class="w-full px-4 py-2 bg-gray-900 rounded border border-gray-700 focus:outline-none focus:ring-2 focus:ring-purple-500">
        </div>
        <div>
          <label class="block mb-2">ZIP File</label>
          <input type="file" id="zipFile" accept=".zip" required
            class="w-full px-4 py-2 bg-gray-900 rounded border border-gray-700">
        </div>
        <button type="submit" class="bg-purple-600 hover:bg-purple-700 px-6 py-2 rounded-lg font-semibold">Upload & Extract</button>
      </form>
      <div id="uploadMessage" class="mt-4"></div>
    </div>
    
    <!-- Projects List -->
    <div class="bg-gray-800 rounded-lg overflow-hidden">
      <table class="w-full">
        <thead class="bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left">Project Name</th>
            <th class="px-6 py-3 text-left">Files</th>
            <th class="px-6 py-3 text-left">URL</th>
            <th class="px-6 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${projects.length === 0 ?
            '<tr><td colspan="4" class="px-6 py-8 text-center text-gray-400">No projects found. Upload your first project!</td></tr>' :
            projects.map(p => `
              <tr class="border-t border-gray-700 hover:bg-gray-700/50">
                <td class="px-6 py-4 font-mono">${p.name}</td>
                <td class="px-6 py-4">${p.files} files</td>
                <td class="px-6 py-4"><a href="${getProjectBaseUrl(p.name)}" target="_blank" class="text-blue-400 hover:text-blue-300">${getProjectBaseUrl(p.name)}</a></td>
                <td class="px-6 py-4 text-right">
                  <button onclick="deleteProject('${p.name}')" class="text-red-400 hover:text-red-300">Delete</button>
                </td>
              </tr>
            `).join("")}
        </tbody>
      </table>
    </div>
  </div>
  
  <script>
    async function uploadProject(e) {
      e.preventDefault();
      const msg = document.getElementById('uploadMessage');
      const projectName = document.getElementById('projectName').value;
      const zipFile = document.getElementById('zipFile').files[0];
      
      if (!zipFile) {
        msg.innerHTML = '<div class="bg-red-600 text-white px-4 py-2 rounded">Please select a ZIP file</div>';
        return;
      }
      
      const formData = new FormData();
      formData.append('file', zipFile);
      if (projectName) formData.append('project_name', projectName);
      
      msg.innerHTML = '<div class="bg-blue-600 text-white px-4 py-2 rounded">Uploading and extracting...</div>';
      
      try {
        const res = await fetch('/admin/pages/upload', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.success) {
          msg.innerHTML = '<div class="bg-green-600 text-white px-4 py-2 rounded">Project uploaded successfully!</div>';
          setTimeout(() => location.reload(), 1500);
        } else {
          msg.innerHTML = '<div class="bg-red-600 text-white px-4 py-2 rounded">Error: ' + data.error + '</div>';
        }
      } catch (err) {
        msg.innerHTML = '<div class="bg-red-600 text-white px-4 py-2 rounded">Error: ' + err.message + '</div>';
      }
    }
    
    async function deleteProject(name) {
      if (!confirm('Delete project: ' + name + '? This will remove all files.')) return;
      try {
        const res = await fetch('/admin/pages/' + name, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
          location.reload();
        } else {
          alert('Error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  </script>
</body>
</html>`;
}

function getDatabaseExplorerPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V8Box - Database Explorer</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
    <div class="flex justify-between items-center">
      <h1 class="text-2xl font-bold text-purple-400">Database Explorer</h1>
      <div class="space-x-4">
        <a href="/admin" class="text-gray-400 hover:text-white">Workers</a>
        <a href="/admin/pages" class="text-gray-400 hover:text-white">Pages</a>
        <a href="/admin/database" class="text-purple-400 hover:text-purple-300">Database</a>
        <a href="/admin/s3" class="text-gray-400 hover:text-white">S3 Browser</a>
        <a href="/admin/logout" class="text-red-400 hover:text-red-300">Logout</a>
      </div>
    </div>
  </nav>
  
  <div class="container mx-auto px-6 py-8">
    <div id="dbMessage" class="mb-6"></div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
      <div class="bg-gray-800 rounded-lg p-6">
        <h2 class="text-xl font-bold mb-4">Database Management</h2>
        <div class="mb-4">
          <label class="block mb-2 text-sm text-gray-300">Active Database</label>
          <div class="flex gap-2">
            <select id="databaseSelect" class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2"></select>
            <button onclick="loadDatabases()" class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded">Refresh</button>
          </div>
        </div>
        <div class="mb-4">
          <label class="block mb-2 text-sm text-gray-300">Create New Database</label>
          <div class="flex gap-2">
            <input id="newDatabaseName" type="text" placeholder="crm"
              class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2" />
            <button onclick="createDatabase()" class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded">Create</button>
          </div>
        </div>
        <button onclick="deleteDatabase()" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded">Delete Active Database</button>
      </div>

      <div class="bg-gray-800 rounded-lg p-6">
        <h2 class="text-xl font-bold mb-4">Table Management</h2>
        <div class="mb-4">
          <label class="block mb-2 text-sm text-gray-300">Active Table</label>
          <div class="flex gap-2">
            <select id="tableSelect" class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2"></select>
            <button onclick="loadTables()" class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded">Refresh</button>
          </div>
        </div>
        <div class="mb-4">
          <label class="block mb-2 text-sm text-gray-300">Table Name</label>
          <input id="newTableName" type="text" placeholder="customers"
            class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2" />
        </div>
        <div class="mb-4">
          <label class="block mb-2 text-sm text-gray-300">Columns (JSON Array)</label>
          <textarea id="tableColumns" rows="6" class="w-full bg-gray-900 text-green-400 font-mono text-xs p-3 rounded border border-gray-700">[
  {"name":"id","type":"INTEGER","primaryKey":true,"autoIncrement":true},
  {"name":"name","type":"TEXT","nullable":false},
  {"name":"email","type":"TEXT","unique":true},
  {"name":"status","type":"TEXT","default":"active"}
]</textarea>
        </div>
        <div class="flex flex-wrap gap-2">
          <button onclick="createTable()" class="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded">Create Table</button>
          <button onclick="deleteTable()" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded">Delete Active Table</button>
          <button onclick="readRows()" class="bg-indigo-600 hover:bg-indigo-700 px-4 py-2 rounded">Refresh Table Content</button>
        </div>
      </div>
    </div>

    <div class="bg-gray-800 rounded-lg p-6 mb-6">
      <h2 class="text-xl font-bold mb-4">Rows CRUD</h2>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <label class="block mb-2 text-sm text-gray-300">Insert Row (JSON Object)</label>
          <textarea id="insertRowData" rows="6" class="w-full bg-gray-900 text-green-400 font-mono text-xs p-3 rounded border border-gray-700">{
  "name": "Andi",
  "email": "andi@example.com",
  "status": "active"
}</textarea>
          <button onclick="insertRow()" class="mt-3 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">Insert Row</button>
          <button onclick="readRows()" class="mt-3 ml-2 bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded">Read Rows</button>
        </div>

        <div>
          <label class="block mb-2 text-sm text-gray-300">Where Filter</label>
          <input id="whereClause" type="text" value="email = ?"
            class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 mb-2" />
          <label class="block mb-2 text-sm text-gray-300">Where Args (JSON Array)</label>
          <textarea id="whereArgs" rows="3" class="w-full bg-gray-900 text-green-400 font-mono text-xs p-3 rounded border border-gray-700 mb-2">["andi@example.com"]</textarea>
          <label class="block mb-2 text-sm text-gray-300">Update Data (JSON Object)</label>
          <textarea id="updateWhereData" rows="3" class="w-full bg-gray-900 text-green-400 font-mono text-xs p-3 rounded border border-gray-700">{
  "status": "inactive"
}</textarea>
          <div class="mt-3">
            <button onclick="searchRows()" class="bg-cyan-600 hover:bg-cyan-700 px-4 py-2 rounded">Search</button>
            <button onclick="updateRowsByWhere()" class="ml-2 bg-yellow-600 hover:bg-yellow-700 px-4 py-2 rounded">Update</button>
            <button onclick="deleteRowsByWhere()" class="ml-2 bg-red-600 hover:bg-red-700 px-4 py-2 rounded">Delete</button>
          </div>
        </div>
      </div>
    </div>

    <div class="bg-gray-800 rounded-lg p-6 mb-6">
      <h2 class="text-2xl font-bold mb-4">Execute SQL Query</h2>
      <div class="mb-4">
        <label class="block mb-2 text-sm text-gray-300">Database (global atau nama database)</label>
        <input id="databaseName" type="text" placeholder="global"
          class="w-full bg-gray-900 text-white font-mono text-sm p-3 rounded border border-gray-700 focus:outline-none focus:ring-2 focus:ring-purple-500" />
      </div>
      <textarea id="sqlQuery" rows="6" placeholder="SELECT * FROM users LIMIT 10;" 
        class="w-full bg-gray-900 text-green-400 font-mono text-sm p-4 rounded border border-gray-700 focus:outline-none focus:ring-2 focus:ring-purple-500"></textarea>
      <button onclick="executeQuery()" class="mt-4 bg-purple-600 hover:bg-purple-700 px-6 py-2 rounded-lg font-semibold">Execute</button>
    </div>
    
    <div id="results" class="bg-gray-800 rounded-lg p-6">
      <h3 class="text-xl font-bold mb-4">Results</h3>
      <div id="resultsContent" class="text-gray-400">Enter a query and click Execute</div>
    </div>
  </div>
  
  <script>
    function getActiveDatabase() {
      const selected = document.getElementById('databaseSelect');
      if (!selected || !selected.value) return 'global';
      return selected.value;
    }

    function getActiveTable() {
      const selected = document.getElementById('tableSelect');
      return selected && selected.value ? selected.value : '';
    }

    function showMessage(type, message) {
      const el = document.getElementById('dbMessage');
      const colors = {
        success: 'bg-green-600',
        error: 'bg-red-600',
        info: 'bg-blue-600',
      };
      el.innerHTML = '<div class="' + (colors[type] || colors.info) + ' text-white px-4 py-2 rounded">' + message + '</div>';
      setTimeout(() => {
        if (el.innerHTML.includes(message)) {
          el.innerHTML = '';
        }
      }, 3000);
    }

    function escapeHtml(value) {
      return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    async function loadDatabases() {
      try {
        const res = await fetch('/admin/database/databases');
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Failed to load databases');
          return;
        }

        const select = document.getElementById('databaseSelect');
        const current = select.value || 'global';
        const databases = data.data.databases || [];
        select.innerHTML = databases.map((name) => '<option value="' + escapeHtml(name) + '">' + escapeHtml(name) + '</option>').join('');
        select.value = databases.includes(current) ? current : (databases[0] || 'global');
        document.getElementById('databaseName').value = select.value || 'global';
        await loadTables();
      } catch (err) {
        showMessage('error', 'Failed to load databases: ' + err.message);
      }
    }

    async function createDatabase() {
      const name = document.getElementById('newDatabaseName').value.trim();
      if (!name) {
        showMessage('error', 'Database name is required');
        return;
      }

      try {
        const res = await fetch('/admin/database/databases', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Failed to create database');
          return;
        }
        showMessage('success', 'Database created: ' + name);
        document.getElementById('newDatabaseName').value = '';
        await loadDatabases();
        document.getElementById('databaseSelect').value = name;
        document.getElementById('databaseName').value = name;
        await loadTables();
      } catch (err) {
        showMessage('error', 'Failed to create database: ' + err.message);
      }
    }

    async function deleteDatabase() {
      const database = getActiveDatabase();
      if (database === 'global') {
        showMessage('error', 'Database global tidak bisa dihapus');
        return;
      }
      if (!confirm('Delete database ' + database + '?')) return;

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database), { method: 'DELETE' });
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Failed to delete database');
          return;
        }
        showMessage('success', 'Database deleted: ' + database);
        await loadDatabases();
      } catch (err) {
        showMessage('error', 'Failed to delete database: ' + err.message);
      }
    }

    async function loadTables() {
      const database = getActiveDatabase();
      document.getElementById('databaseName').value = database;

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables');
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Failed to load tables');
          return;
        }

        const tables = data.data.tables || [];
        const select = document.getElementById('tableSelect');
        const current = select.value || '';
        select.innerHTML = tables.map((name) => '<option value="' + escapeHtml(name) + '">' + escapeHtml(name) + '</option>').join('');
        if (tables.length > 0) {
          select.value = tables.includes(current) ? current : tables[0];
        }
      } catch (err) {
        showMessage('error', 'Failed to load tables: ' + err.message);
      }
    }

    async function createTable() {
      const database = getActiveDatabase();
      const tableName = document.getElementById('newTableName').value.trim();
      const columnsRaw = document.getElementById('tableColumns').value;

      if (!tableName) {
        showMessage('error', 'Table name is required');
        return;
      }

      let columns;
      try {
        columns = JSON.parse(columnsRaw);
      } catch {
        showMessage('error', 'Columns JSON is invalid');
        return;
      }

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tableName, columns }),
        });
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Failed to create table');
          return;
        }
        showMessage('success', 'Table created: ' + tableName);
        document.getElementById('newTableName').value = '';
        await loadTables();
        document.getElementById('tableSelect').value = tableName;
      } catch (err) {
        showMessage('error', 'Failed to create table: ' + err.message);
      }
    }

    async function deleteTable() {
      const database = getActiveDatabase();
      const table = getActiveTable();

      if (!table) {
        showMessage('error', 'Pilih table terlebih dahulu');
        return;
      }

      if (!confirm('Delete table ' + table + ' di database ' + database + '?')) return;

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables/' + encodeURIComponent(table), {
          method: 'DELETE',
        });
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Failed to delete table');
          return;
        }

        showMessage('success', 'Table deleted: ' + table);
        await loadTables();
        document.getElementById('resultsContent').innerHTML = '<div class="text-gray-400">Table deleted. Select table lain untuk lihat isi.</div>';
      } catch (err) {
        showMessage('error', 'Failed to delete table: ' + err.message);
      }
    }

    async function insertRow() {
      const database = getActiveDatabase();
      const table = getActiveTable();
      if (!table) {
        showMessage('error', 'Pilih table terlebih dahulu');
        return;
      }

      let rowData;
      try {
        rowData = JSON.parse(document.getElementById('insertRowData').value);
      } catch {
        showMessage('error', 'Insert row JSON tidak valid');
        return;
      }

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables/' + encodeURIComponent(table) + '/rows', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: rowData }),
        });
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Failed to insert row');
          return;
        }
        showMessage('success', 'Row inserted. Affected: ' + (data.data.rowsAffected || 0));
        await readRows();
      } catch (err) {
        showMessage('error', 'Failed to insert row: ' + err.message);
      }
    }

    async function readRows() {
      const database = getActiveDatabase();
      const table = getActiveTable();
      if (!table) {
        showMessage('error', 'Pilih table terlebih dahulu');
        return;
      }

      const resultsContent = document.getElementById('resultsContent');
      resultsContent.innerHTML = '<div class="text-blue-400">Loading rows...</div>';

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables/' + encodeURIComponent(table) + '/rows?limit=50&order=DESC');
        const data = await res.json();
        if (!data.success) {
          resultsContent.innerHTML = '<div class="text-red-400">Error: ' + (data.error || 'Failed to read rows') + '</div>';
          return;
        }

        renderRowsResult(data.data);
      } catch (err) {
        resultsContent.innerHTML = '<div class="text-red-400">Error: ' + err.message + '</div>';
      }
    }

    function parseWherePayload() {
      const where = document.getElementById('whereClause').value.trim();
      const whereArgsRaw = document.getElementById('whereArgs').value.trim() || '[]';

      if (!where) {
        throw new Error('Where clause is required');
      }

      let whereArgs;
      try {
        whereArgs = JSON.parse(whereArgsRaw);
      } catch {
        throw new Error('Where args JSON tidak valid');
      }

      if (!Array.isArray(whereArgs)) {
        throw new Error('Where args harus array');
      }

      return { where, whereArgs };
    }

    async function searchRows() {
      const database = getActiveDatabase();
      const table = getActiveTable();
      if (!table) {
        showMessage('error', 'Pilih table terlebih dahulu');
        return;
      }

      let wherePayload;
      try {
        wherePayload = parseWherePayload();
      } catch (err) {
        showMessage('error', err.message);
        return;
      }

      const resultsContent = document.getElementById('resultsContent');
      resultsContent.innerHTML = '<div class="text-blue-400">Searching rows...</div>';

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables/' + encodeURIComponent(table) + '/rows/search', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...wherePayload, limit: 50, offset: 0, order: 'DESC' }),
        });
        const data = await res.json();
        if (!data.success) {
          resultsContent.innerHTML = '<div class="text-red-400">Error: ' + (data.error || 'Search failed') + '</div>';
          return;
        }
        renderRowsResult(data.data);
      } catch (err) {
        resultsContent.innerHTML = '<div class="text-red-400">Error: ' + err.message + '</div>';
      }
    }

    async function updateRowsByWhere() {
      const database = getActiveDatabase();
      const table = getActiveTable();
      if (!table) {
        showMessage('error', 'Pilih table terlebih dahulu');
        return;
      }

      let wherePayload;
      let updateData;
      try {
        wherePayload = parseWherePayload();
        updateData = JSON.parse(document.getElementById('updateWhereData').value);
      } catch (err) {
        showMessage('error', err.message || 'Payload tidak valid');
        return;
      }

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables/' + encodeURIComponent(table) + '/rows', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: updateData, ...wherePayload }),
        });
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Update failed');
          return;
        }
        showMessage('success', 'Rows updated: ' + (data.data.rowsAffected || 0));
        await searchRows();
      } catch (err) {
        showMessage('error', 'Update failed: ' + err.message);
      }
    }

    async function deleteRowsByWhere() {
      const database = getActiveDatabase();
      const table = getActiveTable();
      if (!table) {
        showMessage('error', 'Pilih table terlebih dahulu');
        return;
      }

      let wherePayload;
      try {
        wherePayload = parseWherePayload();
      } catch (err) {
        showMessage('error', err.message);
        return;
      }

      if (!confirm('Delete rows di table ' + table + ' dengan filter saat ini?')) return;

      try {
        const res = await fetch('/admin/database/databases/' + encodeURIComponent(database) + '/tables/' + encodeURIComponent(table) + '/rows', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(wherePayload),
        });
        const data = await res.json();
        if (!data.success) {
          showMessage('error', data.error || 'Delete failed');
          return;
        }
        showMessage('success', 'Rows deleted: ' + (data.data.rowsAffected || 0));
        await readRows();
      } catch (err) {
        showMessage('error', 'Delete failed: ' + err.message);
      }
    }

    function renderRowsResult(result) {
      const resultsContent = document.getElementById('resultsContent');
      if (!result.rows || result.rows.length === 0) {
        resultsContent.innerHTML = '<div class="text-gray-400">No rows found</div>';
        return;
      }

      let html = '<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-gray-700"><tr>';
      (result.columns || []).forEach((col) => {
        html += '<th class="px-4 py-2 text-left">' + escapeHtml(col) + '</th>';
      });
      html += '</tr></thead><tbody>';
      result.rows.forEach((row, i) => {
        html += '<tr class="' + (i % 2 === 0 ? 'bg-gray-900' : 'bg-gray-800') + '">';
        Object.values(row).forEach((val) => {
          html += '<td class="px-4 py-2">' + (val !== null ? escapeHtml(val) : '<span class="text-gray-500">NULL</span>') + '</td>';
        });
        html += '</tr>';
      });
      html += '</tbody></table></div>';
      html += '<div class="mt-4 text-gray-400">Rows returned: ' + result.rows.length + '</div>';
      resultsContent.innerHTML = html;
    }

    async function executeQuery() {
      const query = document.getElementById('sqlQuery').value;
      const database = (document.getElementById('databaseName').value || 'global').trim() || 'global';
      const resultsContent = document.getElementById('resultsContent');
      
      if (!query.trim()) {
        resultsContent.innerHTML = '<div class="text-red-400">Please enter a query</div>';
        return;
      }
      
      resultsContent.innerHTML = '<div class="text-blue-400">Executing query...</div>';
      
      try {
        const res = await fetch('/admin/database/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'query=' + encodeURIComponent(query) + '&database=' + encodeURIComponent(database)
        });
        const data = await res.json();
        
        if (data.success) {
          const result = data.data || {};
          if (result.rows && result.rows.length > 0) {
            renderRowsResult(result);
          } else {
            resultsContent.innerHTML = '<div class="text-green-400">Query executed successfully. Rows affected: ' + (result.rowsAffected || 0) + '</div>';
          }
        } else {
          resultsContent.innerHTML = '<div class="text-red-400">Error: ' + data.error + '</div>';
        }
      } catch (err) {
        resultsContent.innerHTML = '<div class="text-red-400">Error: ' + err.message + '</div>';
      }
    }

    document.getElementById('databaseSelect').addEventListener('change', async () => {
      const activeDb = getActiveDatabase();
      document.getElementById('databaseName').value = activeDb;
      await loadTables();
    });

    document.getElementById('tableSelect').addEventListener('change', async () => {
      if (getActiveTable()) {
        await readRows();
      }
    });

    loadDatabases();
  </script>
</body>
</html>`;
}

function getS3BrowserPage(buckets: S3Bucket[], selectedBucket: string, objects: S3Object[], error?: string): string {
  const selectedBucketSafe = escapeHtml(selectedBucket);
  const bucketOptions = buckets.map((bucket) => {
    const safeName = escapeHtml(bucket.name);
    const selected = bucket.name === selectedBucket ? "selected" : "";
    return `<option value="${safeName}" ${selected}>${safeName}</option>`;
  }).join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>V8Box - S3 Browser</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white">
  <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
    <div class="flex justify-between items-center">
      <h1 class="text-2xl font-bold text-purple-400">S3 Browser</h1>
      <div class="space-x-4">
        <a href="/admin" class="text-gray-400 hover:text-white">Workers</a>
        <a href="/admin/pages" class="text-gray-400 hover:text-white">Pages</a>
        <a href="/admin/database" class="text-gray-400 hover:text-white">Database</a>
        <a href="/admin/s3" class="text-purple-400 hover:text-purple-300">S3 Browser</a>
        <a href="/admin/logout" class="text-red-400 hover:text-red-300">Logout</a>
      </div>
    </div>
  </nav>
  
  <div class="container mx-auto px-6 py-8">
    <h2 class="text-2xl font-bold mb-6">Bucket Management</h2>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
      <div class="bg-gray-800 rounded-lg p-4">
        <label class="block text-sm text-gray-300 mb-2">Active Bucket</label>
        <select id="bucketSelect" onchange="switchBucket()" class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2">
          ${bucketOptions || '<option value="">No buckets available</option>'}
        </select>
      </div>
      <div class="bg-gray-800 rounded-lg p-4">
        <label class="block text-sm text-gray-300 mb-2">Create New Bucket</label>
        <div class="flex gap-2">
          <input id="newBucketName" type="text" placeholder="my-project-bucket" class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2">
          <button onclick="createBucket()" class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded">Create</button>
        </div>
      </div>
    </div>

    <div class="flex flex-wrap gap-2 mb-6">
      <button onclick="renameBucket()" class="bg-yellow-600 hover:bg-yellow-700 px-4 py-2 rounded">Edit Bucket</button>
      <button onclick="deleteBucket()" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded">Delete Bucket</button>
    </div>

    <div class="bg-gray-800 rounded-lg p-4 mb-6">
      <label class="block text-sm text-gray-300 mb-2">Upload File ke Bucket Aktif</label>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
        <input id="uploadFile" type="file" class="bg-gray-900 border border-gray-700 rounded px-3 py-2">
        <input id="uploadKey" type="text" placeholder="object key (opsional)" class="bg-gray-900 border border-gray-700 rounded px-3 py-2">
        <button onclick="uploadObject()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">Upload</button>
      </div>
      <p class="text-xs text-gray-400 mt-2">Jika object key kosong, nama file akan dipakai.</p>
    </div>

    <h3 class="text-xl font-semibold mb-4">Active Bucket: ${selectedBucketSafe || "-"}</h3>
    
    ${error ? `<div class="bg-red-600 text-white px-4 py-3 rounded mb-6">Error: ${error}</div>` : ""}
    
    <div class="bg-gray-800 rounded-lg overflow-hidden">
      <table class="w-full">
        <thead class="bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left">Key</th>
            <th class="px-6 py-3 text-left">Size</th>
            <th class="px-6 py-3 text-left">Last Modified</th>
            <th class="px-6 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${objects.length === 0 ?
            '<tr><td colspan="4" class="px-6 py-8 text-center text-gray-400">No objects found in bucket</td></tr>' :
            objects.map(obj => `
              <tr class="border-t border-gray-700 hover:bg-gray-700/50">
                <td class="px-6 py-4 font-mono text-sm">${escapeHtml(obj.key)}</td>
                <td class="px-6 py-4">${(obj.size / 1024).toFixed(2)} KB</td>
                <td class="px-6 py-4">${obj.lastModified ? new Date(obj.lastModified).toLocaleString() : "-"}</td>
                <td class="px-6 py-4 text-right">
                  <button onclick='deleteObject(${JSON.stringify(obj.key)})' class="text-red-400 hover:text-red-300">Delete</button>
                </td>
              </tr>
            `).join("")}
        </tbody>
      </table>
    </div>
  </div>
  
  <script>
    const activeBucket = ${JSON.stringify(selectedBucket)};

    function switchBucket() {
      const selected = document.getElementById('bucketSelect').value;
      if (!selected) return;
      location.href = '/admin/s3?bucket=' + encodeURIComponent(selected);
    }

    async function createBucket() {
      const bucketName = document.getElementById('newBucketName').value.trim().toLowerCase();
      if (!bucketName) {
        alert('Bucket name is required');
        return;
      }

      try {
        const res = await fetch('/admin/s3/buckets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'bucketName=' + encodeURIComponent(bucketName)
        });
        const data = await res.json();
        if (data.success) {
          location.href = '/admin/s3?bucket=' + encodeURIComponent(bucketName);
        } else {
          alert('Error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function renameBucket() {
      if (!activeBucket) {
        alert('No active bucket selected');
        return;
      }

      const newName = prompt('Rename bucket ' + activeBucket + ' to:', activeBucket);
      if (!newName || newName.trim().toLowerCase() === activeBucket) return;

      try {
        const res = await fetch('/admin/s3/buckets/' + encodeURIComponent(activeBucket), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'newName=' + encodeURIComponent(newName.trim().toLowerCase())
        });
        const data = await res.json();
        if (data.success) {
          location.href = '/admin/s3?bucket=' + encodeURIComponent(newName.trim().toLowerCase());
        } else {
          alert('Error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function deleteBucket() {
      if (!activeBucket) {
        alert('No active bucket selected');
        return;
      }

      if (!confirm('Delete bucket ' + activeBucket + ' and all objects inside it?')) return;

      try {
        const res = await fetch('/admin/s3/buckets/' + encodeURIComponent(activeBucket), { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
          location.href = '/admin/s3';
        } else {
          alert('Error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function deleteObject(key) {
      if (!activeBucket) {
        alert('No active bucket selected');
        return;
      }

      if (!confirm('Delete object: ' + key + '?')) return;
      try {
        const res = await fetch('/admin/s3/object/' + encodeURIComponent(key) + '?bucket=' + encodeURIComponent(activeBucket), { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
          location.reload();
        } else {
          alert('Error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function uploadObject() {
      if (!activeBucket) {
        alert('No active bucket selected');
        return;
      }

      const fileInput = document.getElementById('uploadFile');
      const keyInput = document.getElementById('uploadKey');
      const file = fileInput.files && fileInput.files[0];

      if (!file) {
        alert('Pilih file terlebih dahulu');
        return;
      }

      const formData = new FormData();
      formData.append('bucket', activeBucket);
      formData.append('file', file);
      if (keyInput.value.trim()) {
        formData.append('key', keyInput.value.trim());
      }

      try {
        const res = await fetch('/admin/s3/object', {
          method: 'POST',
          body: formData,
        });
        const data = await res.json();
        if (data.success) {
          location.reload();
        } else {
          alert('Error: ' + data.error);
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  </script>
</body>
</html>`;
}

// ============================================================================
// START SERVER
// ============================================================================

console.log(`🚀 V8Box Server starting on port ${config.port}...`);
console.log(`📦 Services initialized:`);
console.log(`   - LibSQL: ${config.libsqlUrl}`);
console.log(`   - Valkey: ${config.valkeyUrl}`);
console.log(`   - S3: ${config.s3Endpoint}`);
console.log(`     • Default bucket: ${config.s3DefaultBucket}`);
console.log(`     • Projects bucket: ${config.s3ProjectsBucket}`);
console.log(`     • Functions bucket: ${config.s3FunctionsBucket}`);
console.log(`\n🌐 Access points:`);
if (isLocalhostMode) {
  console.log(`   - Admin: http://localhost:${config.port}/admin`);
  console.log(`   - API: http://localhost:${config.port}/run/:func`);
  console.log(`   - Pages: http://localhost:${config.port}/pages/:project`);
} else {
  console.log(`   - Admin: http://admin.${config.domain}:${config.port}`);
  console.log(`   - API: http://api.${config.domain}:${config.port}/run/:func`);
  console.log(`   - Pages: http://*.${config.domain}:${config.port}`);
}
console.log(`\n🔐 Admin password: ${config.adminPassword}\n`);

Deno.serve({ port: config.port }, app.fetch);

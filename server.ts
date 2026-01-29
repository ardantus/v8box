import {
    Hono,
    getCookie,
    setCookie,
    deleteCookie,
    createClient,
    connect,
    S3Client,
    ListObjectsV2Command,
    DeleteObjectCommand,
    GetObjectCommand,
    JSZip,
    exists,
    join,
    extname,
    basename,
    ensureDir,
} from "./deps.ts";
import type { Context, Next } from "./deps.ts";
import type { ServiceContext, ApiResponse, ExecutionLog, PageProject, S3Object } from "./types.ts";

// ============================================================================
// CONFIGURATION
// ============================================================================

const config = {
    adminPassword: Deno.env.get("ADMIN_PASSWORD") || "admin123",
    libsqlUrl: Deno.env.get("LIBSQL_URL") || "http://localhost:8080",
    libsqlAuthToken: Deno.env.get("LIBSQL_AUTH_TOKEN"),
    valkeyUrl: Deno.env.get("VALKEY_URL") || "redis://localhost:6379",
    s3Endpoint: Deno.env.get("S3_ENDPOINT") || "http://localhost:8333",
    s3AccessKey: Deno.env.get("S3_ACCESS_KEY") || "",
    s3SecretKey: Deno.env.get("S3_SECRET_KEY") || "",
    s3Bucket: Deno.env.get("S3_BUCKET") || "v8box",
    s3Region: Deno.env.get("S3_REGION") || "us-east-1",
    domain: Deno.env.get("DOMAIN") || "domain.tld",
    port: parseInt(Deno.env.get("PORT") || "8000"),
};

// ============================================================================
// SERVICE INITIALIZATION
// ============================================================================

// LibSQL Client
const db = createClient({
    url: config.libsqlUrl,
    authToken: config.libsqlAuthToken,
});

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
    const parts = hostname.split(".");
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
    if (subdomain !== "admin") {
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

// Execute SQL Query
app.post("/admin/database/query", adminAuth, async (c) => {
    const body = await c.req.parseBody();
    const query = body.query as string;

    try {
        const result = await db.execute(query);
        return c.json<ApiResponse>({
            success: true,
            data: {
                rows: result.rows,
                columns: result.columns,
                rowsAffected: result.rowsAffected,
            },
        });
    } catch (error) {
        return c.json<ApiResponse>({ success: false, error: String(error) }, 500);
    }
});

// S3 Browser
app.get("/admin/s3", adminAuth, async (c) => {
    try {
        const command = new ListObjectsV2Command({ Bucket: config.s3Bucket });
        const response = await s3.send(command);

        const objects: S3Object[] = (response.Contents || []).map((obj) => ({
            key: obj.Key || "",
            size: obj.Size || 0,
            lastModified: obj.LastModified,
        }));

        return c.html(getS3BrowserPage(objects));
    } catch (error) {
        return c.html(getS3BrowserPage([], String(error)));
    }
});

// Delete S3 Object
app.delete("/admin/s3/:key", adminAuth, async (c) => {
    const key = c.req.param("key");

    try {
        const command = new DeleteObjectCommand({
            Bucket: config.s3Bucket,
            Key: key,
        });
        await s3.send(command);
        return c.json<ApiResponse>({ success: true });
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

    if (subdomain !== "api") {
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

app.get("/*", async (c) => {
    const subdomain = c.get("subdomain");

    // Skip admin and api subdomains
    if (subdomain === "admin" || subdomain === "api" || !subdomain) {
        return c.notFound();
    }

    if (!isValidName(subdomain)) {
        return c.text("Invalid subdomain", 400);
    }

    const path = c.req.path === "/" ? "/index.html" : c.req.path;
    const filePath = join("./storage/pages", subdomain, path);

    try {
        // Check if file exists
        if (!await exists(filePath)) {
            // Try index.html for directories
            const indexPath = join(filePath, "index.html");
            if (await exists(indexPath)) {
                const content = await Deno.readFile(indexPath);
                return c.body(content, 200, { "Content-Type": "text/html" });
            }
            return c.notFound();
        }

        const stat = await Deno.stat(filePath);

        // If directory, try index.html
        if (stat.isDirectory) {
            const indexPath = join(filePath, "index.html");
            if (await exists(indexPath)) {
                const content = await Deno.readFile(indexPath);
                return c.body(content, 200, { "Content-Type": "text/html" });
            }
            return c.text("Directory listing not allowed", 403);
        }

        // Serve file
        const content = await Deno.readFile(filePath);
        const ext = extname(filePath);
        const mimeType = getMimeType(ext);

        return c.body(content, 200, { "Content-Type": mimeType });
    } catch (error) {
        console.error("Error serving file:", error);
        return c.notFound();
    }
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
      window.open('http://api.${config.domain}:${config.port}/run/' + funcName, '_blank');
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
                <td class="px-6 py-4"><a href="http://${p.name}.${config.domain}:${config.port}" target="_blank" class="text-blue-400 hover:text-blue-300">http://${p.name}.${config.domain}:${config.port}</a></td>
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
    <div class="bg-gray-800 rounded-lg p-6 mb-6">
      <h2 class="text-2xl font-bold mb-4">Execute SQL Query</h2>
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
    async function executeQuery() {
      const query = document.getElementById('sqlQuery').value;
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
          body: 'query=' + encodeURIComponent(query)
        });
        const data = await res.json();
        
        if (data.success) {
          const result = data.data;
          if (result.rows && result.rows.length > 0) {
            let html = '<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-gray-700"><tr>';
            result.columns.forEach(col => {
              html += '<th class="px-4 py-2 text-left">' + col + '</th>';
            });
            html += '</tr></thead><tbody>';
            result.rows.forEach((row, i) => {
              html += '<tr class="' + (i % 2 === 0 ? 'bg-gray-900' : 'bg-gray-800') + '">';
              Object.values(row).forEach(val => {
                html += '<td class="px-4 py-2">' + (val !== null ? String(val) : '<span class="text-gray-500">NULL</span>') + '</td>';
              });
              html += '</tr>';
            });
            html += '</tbody></table></div>';
            html += '<div class="mt-4 text-gray-400">Rows returned: ' + result.rows.length + '</div>';
            resultsContent.innerHTML = html;
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
  </script>
</body>
</html>`;
}

function getS3BrowserPage(objects: S3Object[], error?: string): string {
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
    <h2 class="text-2xl font-bold mb-6">Bucket: ${config.s3Bucket}</h2>
    
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
                <td class="px-6 py-4 font-mono text-sm">${obj.key}</td>
                <td class="px-6 py-4">${(obj.size / 1024).toFixed(2)} KB</td>
                <td class="px-6 py-4">${obj.lastModified ? new Date(obj.lastModified).toLocaleString() : "-"}</td>
                <td class="px-6 py-4 text-right">
                  <button onclick="deleteObject('${obj.key}')" class="text-red-400 hover:text-red-300">Delete</button>
                </td>
              </tr>
            `).join("")}
        </tbody>
      </table>
    </div>
  </div>
  
  <script>
    async function deleteObject(key) {
      if (!confirm('Delete object: ' + key + '?')) return;
      try {
        const res = await fetch('/admin/s3/' + encodeURIComponent(key), { method: 'DELETE' });
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
console.log(`   - S3: ${config.s3Endpoint} (bucket: ${config.s3Bucket})`);
console.log(`\n🌐 Access points:`);
console.log(`   - Admin: http://admin.${config.domain}:${config.port}`);
console.log(`   - API: http://api.${config.domain}:${config.port}/run/:func`);
console.log(`   - Pages: http://*.${config.domain}:${config.port}`);
console.log(`\n🔐 Admin password: ${config.adminPassword}\n`);

Deno.serve({ port: config.port }, app.fetch);

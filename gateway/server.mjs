import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { createApiHandler } from "./backend.mjs";

const root = normalize(join(dirname(fileURLToPath(import.meta.url)), ".."));
const handleApi = createApiHandler(root);
const apps = {
  "/login": join(root, "Loginqldoanhoi", "dist"),
  "/hoat-dong": join(root, "Quanlyhoatdong", "dist"),
};

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
};

function resolveApp(urlPath) {
  return Object.entries(apps).find(
    ([base]) => urlPath === base || urlPath.startsWith(`${base}/`),
  );
}

async function sendFile(response, filePath) {
  const body = await readFile(filePath);
  const extension = extname(filePath);
  const isHtml = extension === ".html";
  response.writeHead(200, {
    "content-type": contentTypes[extension] ?? "application/octet-stream",
    "cache-control": isHtml
      ? "no-cache"
      : "public, max-age=31536000, immutable",
  });
  response.end(body);
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (await handleApi(request, response, url)) return;

    if (url.pathname === "/") {
      response.writeHead(302, { location: "/hoat-dong/featured" });
      response.end();
      return;
    }

    if (url.pathname === "/login") {
      response.writeHead(302, {
        location: `/login/${url.search}${url.hash}`,
      });
      response.end();
      return;
    }

    const match = resolveApp(url.pathname);
    if (!match) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }

    const [base, distDir] = match;
    const relative = decodeURIComponent(
      url.pathname.slice(base.length),
    ).replace(/^\/+/, "");
    const candidate = relative
      ? join(distDir, relative)
      : join(distDir, "index.html");

    try {
      await sendFile(response, candidate);
    } catch {
      await sendFile(response, join(distDir, "index.html"));
    }
  } catch (error) {
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end(
      error instanceof Error ? error.message : "Internal server error",
    );
  }
});

const port = Number(process.env.PORT ?? 3001);
server.listen(port, () => {
  console.log(`Gateway ready: http://localhost:${port}`);
  console.log(`Login: http://localhost:${port}/login/`);
  console.log(`Hoạt động: http://localhost:${port}/hoat-dong/`);
});

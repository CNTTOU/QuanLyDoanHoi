import { createApiHandler } from "../gateway/backend.mjs";

const handleApi = createApiHandler(process.cwd());

export default async function handler(request, response) {
  const protocol = request.headers["x-forwarded-proto"] ?? "https";
  const host = request.headers.host ?? "localhost";
  const url = new URL(request.url ?? "/", `${protocol}://${host}`);
  if (!url.pathname.startsWith("/api/")) {
    url.pathname = `/api${url.pathname.startsWith("/") ? "" : "/"}${url.pathname}`;
  }

  const handled = await handleApi(request, response, url);
  if (!handled && !response.writableEnded) {
    response.statusCode = 404;
    response.end("API not found");
  }
}

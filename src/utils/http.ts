import type { IncomingMessage, ServerResponse } from "node:http";

export class HttpInputError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "HttpInputError";
  }
}

export function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  method?: string,
  headers: Record<string, string> = {}
): void {
  const serialized = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    vary: "Origin",
    ...headers,
  });
  response.end(method === "HEAD" ? undefined : serialized);
}

export async function readJsonBody(
  request: IncomingMessage,
  maxBytes: number
): Promise<Record<string, unknown>> {
  const contentType = request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new HttpInputError(415, "unsupported_media_type", "Content-Type must be application/json.");
  }

  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new HttpInputError(413, "body_too_large", "Request body is too large.");
  }

  const chunks: Buffer[] = [];
  let size = 0;
  let oversized = false;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBytes) {
      oversized = true;
      continue;
    }
    chunks.push(buffer);
  }
  if (oversized) throw new HttpInputError(413, "body_too_large", "Request body is too large.");

  try {
    const body: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new Error("invalid_object");
    }
    return body as Record<string, unknown>;
  } catch {
    throw new HttpInputError(400, "invalid_json", "Request body must be a JSON object.");
  }
}

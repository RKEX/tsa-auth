import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuthBackendConfig } from "./config/env.js";
import { FixedWindowRateLimiter } from "./middleware/rate-limit.js";
import { AuthServiceError } from "./services/errors.js";
import type { IdTokenVerifier, VerifiedIdentity } from "./services/firebase-auth.js";
import { createAdminSessionToken, verifyAdminSessionToken } from "./services/session.js";
import { HttpInputError, readJsonBody, sendJson } from "./utils/http.js";

const BODY_LIMIT_BYTES = 16 * 1024;

export interface AppDependencies {
  verifyIdToken: IdTokenVerifier;
  now?: () => number;
}

function requestId(request: IncomingMessage): string {
  const value = request.headers["x-request-id"];
  const candidate = Array.isArray(value) ? value[0] : value;
  return candidate && /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/i.test(candidate)
    ? candidate
    : "unassigned";
}

function safeRoute(pathname: string): string {
  return ["/healthz", "/readyz", "/auth/verify", "/auth/session", "/auth/session/verify"].includes(pathname)
    ? pathname
    : "/unmatched";
}

function secureEqual(supplied: string | undefined, expected: string): boolean {
  if (!supplied || supplied.length > 1024) return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function identityPayload(identity: VerifiedIdentity) {
  return {
    uid: identity.uid,
    ...(identity.email ? { email: identity.email } : {}),
    ...(identity.emailVerified !== undefined ? { emailVerified: identity.emailVerified } : {}),
    ...(identity.name ? { name: identity.name } : {}),
  };
}

function isAuthorizedAdmin(identity: VerifiedIdentity, config: AuthBackendConfig): boolean {
  return Boolean(
    identity.email &&
    identity.email.trim().toLowerCase() === config.authorizedAdminEmail.toLowerCase()
  );
}

export function createApp(config: AuthBackendConfig, dependencies: AppDependencies) {
  const limiter = new FixedWindowRateLimiter(config.rateLimitMax, config.rateLimitWindowMs, dependencies.now);

  return async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const startedAt = dependencies.now?.() ?? Date.now();
    const id = requestId(request);
    const method = request.method ?? "GET";
    let pathname = "/";
    try {
      pathname = new URL(request.url ?? "/", "http://localhost").pathname;
      response.setHeader("x-request-id", id);

      if ((method === "GET" || method === "HEAD") && pathname === "/healthz") {
        sendJson(response, 200, { status: "ok" }, method);
        return;
      }
      if ((method === "GET" || method === "HEAD") && pathname === "/readyz") {
        sendJson(response, 200, { ready: true }, method);
        return;
      }
      if (method === "OPTIONS") {
        sendJson(response, 204, {}, method);
        return;
      }
      if (method !== "POST" || !["/auth/verify", "/auth/session", "/auth/session/verify"].includes(pathname)) {
        sendJson(response, 404, { success: false, error: { code: "not_found", message: "Not found." } }, method);
        return;
      }

      const address = request.socket.remoteAddress ?? "unknown";
      if (!limiter.allow(address)) {
        sendJson(response, 429, { success: false, error: { code: "rate_limited", message: "Too many requests." } }, method, { "retry-after": "60" });
        return;
      }

      const internalSecret = request.headers["x-auth-backend-secret"];
      if (!secureEqual(Array.isArray(internalSecret) ? internalSecret[0] : internalSecret, config.backendSharedSecret)) {
        sendJson(response, 401, { success: false, error: { code: "internal_unauthorized", message: "Unauthorized." } }, method);
        return;
      }

      const body = await readJsonBody(request, BODY_LIMIT_BYTES);
      if (pathname === "/auth/session/verify") {
        const sessionToken = body.sessionToken;
        if (typeof sessionToken !== "string") {
          throw new HttpInputError(400, "invalid_request", "A session token is required.");
        }
        const session = verifyAdminSessionToken(
          sessionToken,
          config.adminSessionSecret,
          config.authorizedAdminEmail,
          dependencies.now?.() ?? Date.now()
        );
        if (!session) {
          sendJson(response, 401, { success: false, error: { code: "invalid_session", message: "Session is invalid." } }, method);
          return;
        }
        sendJson(response, 200, {
          success: true,
          user: { uid: session.uid, email: session.email, ...(session.name ? { name: session.name } : {}) },
        }, method);
        return;
      }

      const idToken = body.idToken;
      if (typeof idToken !== "string" || idToken.trim().length === 0 || idToken.length > 12000) {
        throw new HttpInputError(400, "invalid_request", "A valid Firebase ID token is required.");
      }

      const identity = await dependencies.verifyIdToken(idToken.trim());
      if (pathname === "/auth/verify") {
        sendJson(response, 200, { success: true, user: identityPayload(identity) }, method);
        return;
      }

      if (!isAuthorizedAdmin(identity, config)) {
        throw new AuthServiceError("unauthorized", 403, "This account is not authorized for admin access.");
      }
      if (identity.emailVerified === false) {
        throw new AuthServiceError("email_unverified", 403, "This Google account has not verified its email address.");
      }

      const sessionToken = createAdminSessionToken(
        { uid: identity.uid, email: identity.email!, name: identity.name },
        config.adminSessionSecret,
        dependencies.now?.() ?? Date.now()
      );
      sendJson(response, 200, {
        success: true,
        sessionToken,
        user: {
          uid: identity.uid,
          email: identity.email,
          ...(identity.name ? { name: identity.name } : {}),
        },
      }, method);
    } catch (error) {
      if (error instanceof HttpInputError) {
        sendJson(response, error.status, { success: false, error: { code: error.code, message: error.message } }, method);
      } else if (error instanceof AuthServiceError) {
        sendJson(response, error.status, {
          success: false,
          error: { code: error.category, message: error.message },
        }, method);
      } else {
        sendJson(response, 503, {
          success: false,
          error: { code: "provider_unavailable", message: "Authentication provider is unavailable." },
        }, method);
      }
    } finally {
      const status = response.statusCode;
      console.info("auth_request", {
        requestId: id,
        method,
        route: safeRoute(pathname),
        status,
        durationMs: Math.max(0, (dependencies.now?.() ?? Date.now()) - startedAt),
      });
    }
  };
}

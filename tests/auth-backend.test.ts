import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { afterEach, describe, it } from "node:test";
import { createApp } from "../src/app.js";
import { loadConfig, normalizePrivateKey, ConfigurationError } from "../src/config/env.js";
import { classifyFirebaseError } from "../src/services/errors.js";
import type { AuthBackendConfig } from "../src/config/env.js";

const privateKey = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----";
const secret = "test-only-shared-session-secret-long-enough-123456789";
const config: AuthBackendConfig = {
  nodeEnv: "test",
  port: 10000,
  firebaseProjectId: "example-project-12345",
  firebaseClientEmail: "firebase-admin@example.test",
  firebasePrivateKey: privateKey,
  authorizedAdminEmail: "admin@example.test",
  adminSessionSecret: secret,
  backendSharedSecret: "test-only-backend-secret-long-enough-123456789",
  rateLimitMax: 20,
  rateLimitWindowMs: 60000,
};

const servers: Server[] = [];

async function withServer(
  options: {
    verifyIdToken?: (token: string) => Promise<{ uid: string; email?: string; emailVerified?: boolean; name?: string }>;
    override?: Partial<AuthBackendConfig>;
  },
  callback: (baseUrl: string) => Promise<void>
) {
  const app = createApp({ ...config, ...options.override }, {
    verifyIdToken: options.verifyIdToken ?? (async () => ({
      uid: "test-uid",
      email: "admin@example.test",
      emailVerified: true,
      name: "Test Admin",
    })),
  });
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

afterEach(() => {
  servers.length = 0;
});

function internalHeaders() {
  return {
    "content-type": "application/json",
    "x-auth-backend-secret": config.backendSharedSecret,
  };
}

describe("authentication backend", () => {
  it("validates required configuration and normalizes escaped PEM newlines", () => {
    assert.throws(
      () => loadConfig({} as NodeJS.ProcessEnv),
      (error: unknown) => error instanceof ConfigurationError && error.missing.includes("FIREBASE_PROJECT_ID")
    );
    assert.equal(normalizePrivateKey('"-----BEGIN PRIVATE KEY-----\\nYWJj\\n-----END PRIVATE KEY-----"'), privateKey);
  });

  it("serves safe GET and HEAD health checks and a non-revealing readiness response", async () => {
    await withServer({}, async (baseUrl) => {
      const get = await fetch(`${baseUrl}/healthz`);
      assert.equal(get.status, 200);
      assert.deepEqual(await get.json(), { status: "ok" });
      const head = await fetch(`${baseUrl}/healthz`, { method: "HEAD" });
      assert.equal(head.status, 200);
      assert.equal(await head.text(), "");
      const ready = await fetch(`${baseUrl}/readyz`);
      assert.equal(ready.status, 200);
      assert.deepEqual(await ready.json(), { ready: true });
    });
  });

  it("requires the private Cloudflare-to-Render credential and emits no browser CORS permission", async () => {
    await withServer({}, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ idToken: "not-logged" }),
      });
      assert.equal(response.status, 401);
      assert.equal(response.headers.get("access-control-allow-origin"), null);
    });
  });

  it("rejects invalid and expired Firebase ID tokens without leaking provider text", async () => {
    const verifier = async (): Promise<never> => {
      throw classifyFirebaseError(
        Object.assign(new Error("sensitive provider detail must not escape"), { code: "auth/id-token-expired" })
      );
    };
    await withServer({ verifyIdToken: verifier }, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: internalHeaders(),
        body: JSON.stringify({ idToken: "test-only-token" }),
      });
      assert.equal(response.status, 401);
      const body = await response.text();
      assert.match(body, /invalid_token/);
      assert.doesNotMatch(body, /sensitive provider detail|test-only-token/);
    });
  });

  it("classifies revoked tokens as invalid and unknown Firebase failures as unavailable", () => {
    assert.equal(classifyFirebaseError({ code: "auth/id-token-revoked" }).status, 401);
    assert.equal(classifyFirebaseError({ code: "auth/internal-error" }).status, 503);
  });

  it("denies valid non-admin Firebase identities", async () => {
    await withServer({ verifyIdToken: async () => ({ uid: "other", email: "person@example.test", emailVerified: true }) }, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: internalHeaders(),
        body: JSON.stringify({ idToken: "test-only-token" }),
      });
      assert.equal(response.status, 403);
    });
  });

  it("preserves the verified-email requirement for the authorized admin", async () => {
    await withServer({ verifyIdToken: async () => ({ uid: "admin", email: "admin@example.test", emailVerified: false }) }, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: internalHeaders(),
        body: JSON.stringify({ idToken: "test-only-token" }),
      });
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), {
        success: false,
        error: { code: "email_unverified", message: "This Google account has not verified its email address." },
      });
    });
  });

  it("creates a stateless signed session only for the trusted admin and verifies it", async () => {
    await withServer({}, async (baseUrl) => {
      const created = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: internalHeaders(),
        body: JSON.stringify({ idToken: "test-only-token" }),
      });
      assert.equal(created.status, 200);
      const session = await created.json() as { sessionToken: string; user: { email: string } };
      assert.equal(session.user.email, "admin@example.test");
      assert.ok(session.sessionToken);

      const verified = await fetch(`${baseUrl}/auth/session/verify`, {
        method: "POST",
        headers: internalHeaders(),
        body: JSON.stringify({ sessionToken: session.sessionToken }),
      });
      assert.equal(verified.status, 200);
      assert.deepEqual(await verified.json(), {
        success: true,
        user: { uid: "test-uid", email: "admin@example.test", name: "Test Admin" },
      });
    });
  });

  it("rejects malformed and over-limit requests", async () => {
    await withServer({ override: { rateLimitMax: 1 } }, async (baseUrl) => {
      const first = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: internalHeaders(),
        body: "{}",
      });
      assert.equal(first.status, 400);
      const limited = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: internalHeaders(),
        body: "{}",
      });
      assert.equal(limited.status, 429);
    });
    await withServer({}, async (baseUrl) => {
      const body = JSON.stringify({ idToken: "x".repeat(20_000) });
      const oversized = await fetch(`${baseUrl}/auth/session`, {
        method: "POST",
        headers: internalHeaders(),
        body,
      });
      assert.equal(oversized.status, 413);
    });
  });
});

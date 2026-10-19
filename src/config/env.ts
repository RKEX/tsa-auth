export interface AuthBackendConfig {
  nodeEnv: "development" | "test" | "production";
  port: number;
  firebaseProjectId: string;
  firebaseClientEmail: string;
  firebasePrivateKey: string;
  authorizedAdminEmail: string;
  adminSessionSecret: string;
  backendSharedSecret: string;
  rateLimitMax: number;
  rateLimitWindowMs: number;
}

export class ConfigurationError extends Error {
  constructor(readonly missing: string[], readonly invalid: string[]) {
    super("Authentication backend configuration is incomplete or invalid.");
    this.name = "ConfigurationError";
  }
}

export function normalizePrivateKey(value: string): string {
  let normalized = value.trim();
  if (
    (normalized.startsWith('"') && normalized.endsWith('"')) ||
    (normalized.startsWith("'") && normalized.endsWith("'"))
  ) {
    normalized = normalized.slice(1, -1);
  }

  return normalized
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\r\n/g, "\n")
    .trim();
}

function parsePositiveInteger(value: string | undefined, fallback: number): number | undefined {
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AuthBackendConfig {
  const missing: string[] = [];
  const invalid: string[] = [];
  const required = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) missing.push(name);
    return value ?? "";
  };

  const nodeEnvValue = env.NODE_ENV?.trim() || "development";
  if (!["development", "test", "production"].includes(nodeEnvValue)) invalid.push("NODE_ENV");

  const port = parsePositiveInteger(env.PORT, 10000);
  if (port === undefined || port > 65535) invalid.push("PORT");

  const firebaseProjectId = required("FIREBASE_PROJECT_ID");
  if (firebaseProjectId && !/^[a-z0-9][a-z0-9-]{4,28}[a-z0-9]$/.test(firebaseProjectId)) {
    invalid.push("FIREBASE_PROJECT_ID");
  }

  const firebaseClientEmail = required("FIREBASE_CLIENT_EMAIL");
  if (firebaseClientEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(firebaseClientEmail)) {
    invalid.push("FIREBASE_CLIENT_EMAIL");
  }

  const rawPrivateKey = required("FIREBASE_PRIVATE_KEY");
  const firebasePrivateKey = rawPrivateKey ? normalizePrivateKey(rawPrivateKey) : "";
  if (
    firebasePrivateKey &&
    (!firebasePrivateKey.startsWith("-----BEGIN PRIVATE KEY-----") ||
      !firebasePrivateKey.endsWith("-----END PRIVATE KEY-----") ||
      !firebasePrivateKey.includes("\n"))
  ) {
    invalid.push("FIREBASE_PRIVATE_KEY");
  }

  const authorizedAdminEmail = required("AUTHORIZED_ADMIN_EMAIL").toLowerCase();
  if (authorizedAdminEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(authorizedAdminEmail)) {
    invalid.push("AUTHORIZED_ADMIN_EMAIL");
  }

  const adminSessionSecret = required("ADMIN_SESSION_SECRET");
  if (adminSessionSecret && adminSessionSecret.length < 32) invalid.push("ADMIN_SESSION_SECRET");

  const backendSharedSecret = required("AUTH_BACKEND_SHARED_SECRET");
  if (backendSharedSecret && backendSharedSecret.length < 32) invalid.push("AUTH_BACKEND_SHARED_SECRET");

  const rateLimitMax = parsePositiveInteger(env.AUTH_RATE_LIMIT_MAX, 60);
  if (rateLimitMax === undefined) invalid.push("AUTH_RATE_LIMIT_MAX");

  const rateLimitWindowMs = parsePositiveInteger(env.AUTH_RATE_LIMIT_WINDOW_MS, 60000);
  if (rateLimitWindowMs === undefined || rateLimitWindowMs < 1000) {
    invalid.push("AUTH_RATE_LIMIT_WINDOW_MS");
  }

  if (missing.length || invalid.length) throw new ConfigurationError(missing, invalid);

  return {
    nodeEnv: nodeEnvValue as AuthBackendConfig["nodeEnv"],
    port: port!,
    firebaseProjectId,
    firebaseClientEmail,
    firebasePrivateKey,
    authorizedAdminEmail,
    adminSessionSecret,
    backendSharedSecret,
    rateLimitMax: rateLimitMax!,
    rateLimitWindowMs: rateLimitWindowMs!,
  };
}

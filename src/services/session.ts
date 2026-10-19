import { createHmac, timingSafeEqual } from "node:crypto";

export const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;

export interface SessionIdentity {
  uid: string;
  email: string;
  name?: string;
}

export interface AdminSessionPayload extends SessionIdentity {
  issuedAt: number;
  expiresAt: number;
}

export function createAdminSessionToken(
  identity: SessionIdentity,
  secret: string,
  now = Date.now()
): string {
  const payload: AdminSessionPayload = {
    email: identity.email.trim().toLowerCase(),
    uid: identity.uid,
    name: identity.name,
    issuedAt: now,
    expiresAt: now + SESSION_MAX_AGE_SECONDS * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

export function verifyAdminSessionToken(
  token: string,
  secret: string,
  authorizedEmail: string,
  now = Date.now()
): AdminSessionPayload | null {
  if (!token || token.length > 4096 || !secret || secret.length < 32) return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;

  const expected = createHmac("sha256", secret).update(parts[0]).digest();
  let actual: Buffer;
  try {
    actual = Buffer.from(parts[1], "base64url");
  } catch {
    return null;
  }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;

  try {
    const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as Partial<AdminSessionPayload>;
    if (
      typeof payload.uid !== "string" || !payload.uid ||
      typeof payload.email !== "string" ||
      payload.email.trim().toLowerCase() !== authorizedEmail.trim().toLowerCase() ||
      typeof payload.issuedAt !== "number" || !Number.isFinite(payload.issuedAt) ||
      typeof payload.expiresAt !== "number" || !Number.isFinite(payload.expiresAt) ||
      now >= payload.expiresAt || payload.issuedAt > now ||
      (payload.name !== undefined && typeof payload.name !== "string")
    ) return null;
    return payload as AdminSessionPayload;
  } catch {
    return null;
  }
}

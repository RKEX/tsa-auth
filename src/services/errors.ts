export type AuthErrorCategory = "invalid_token" | "unauthorized" | "email_unverified" | "provider_unavailable";

export class AuthServiceError extends Error {
  constructor(
    readonly category: AuthErrorCategory,
    readonly status: number,
    message: string
  ) {
    super(message);
    this.name = "AuthServiceError";
  }
}

const invalidFirebaseCodes = new Set([
  "auth/argument-error",
  "auth/id-token-expired",
  "auth/id-token-revoked",
  "auth/invalid-id-token",
  "auth/user-disabled",
]);

export function classifyFirebaseError(error: unknown): AuthServiceError {
  const code =
    typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
      ? error.code
      : "";
  if (invalidFirebaseCodes.has(code)) {
    return new AuthServiceError("invalid_token", 401, "Firebase ID token is invalid.");
  }
  return new AuthServiceError("provider_unavailable", 503, "Authentication provider is unavailable.");
}

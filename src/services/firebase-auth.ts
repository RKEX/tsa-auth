import { cert, getApps, initializeApp, type App } from "firebase-admin/app";
import { getAuth, type DecodedIdToken } from "firebase-admin/auth";
import type { AuthBackendConfig } from "../config/env.js";
import { classifyFirebaseError, AuthServiceError } from "./errors.js";

export interface VerifiedIdentity {
  uid: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
}

export type IdTokenVerifier = (idToken: string) => Promise<VerifiedIdentity>;

export function validateFirebaseClaims(
  decoded: Omit<Pick<DecodedIdToken, "uid" | "aud" | "iss" | "sub" | "exp" | "iat" | "auth_time" | "email" | "email_verified" | "name">, "name"> & { name?: string },
  projectId: string,
  nowSeconds = Math.floor(Date.now() / 1000)
): VerifiedIdentity {
  if (
    decoded.aud !== projectId ||
    decoded.iss !== `https://securetoken.google.com/${projectId}` ||
    !decoded.uid ||
    decoded.sub !== decoded.uid ||
    !Number.isFinite(decoded.exp) || decoded.exp <= nowSeconds ||
    !Number.isFinite(decoded.iat) || decoded.iat > nowSeconds ||
    !Number.isFinite(decoded.auth_time) || decoded.auth_time > nowSeconds
  ) {
    throw new AuthServiceError("invalid_token", 401, "Firebase ID token claims are invalid.");
  }

  return {
    uid: decoded.uid,
    email: decoded.email,
    emailVerified: decoded.email_verified,
    name: decoded.name,
  };
}

export function createFirebaseAdminApp(config: AuthBackendConfig): App {
  const appName = "student-ambassadors-render-auth";
  const existing = getApps().find((app) => app.name === appName);
  if (existing) return existing;
  return initializeApp(
    {
      credential: cert({
        projectId: config.firebaseProjectId,
        clientEmail: config.firebaseClientEmail,
        privateKey: config.firebasePrivateKey,
      }),
      projectId: config.firebaseProjectId,
    },
    appName
  );
}

export function createFirebaseIdTokenVerifier(config: AuthBackendConfig): IdTokenVerifier {
  const auth = getAuth(createFirebaseAdminApp(config));
  return async (idToken: string) => {
    try {
      // Revocation checking is deliberately enabled for admin sign-in.
      const decoded = await auth.verifyIdToken(idToken, true);
      return validateFirebaseClaims(decoded, config.firebaseProjectId);
    } catch (error) {
      if (error instanceof AuthServiceError) throw error;
      throw classifyFirebaseError(error);
    }
  };
}

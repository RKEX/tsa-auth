import { createServer } from "node:http";
import { loadConfig, ConfigurationError } from "./config/env.js";
import { createApp } from "./app.js";
import { createFirebaseIdTokenVerifier } from "./services/firebase-auth.js";
import type { AuthBackendConfig } from "./config/env.js";

let config: AuthBackendConfig;
try {
  config = loadConfig();
} catch (error) {
  if (error instanceof ConfigurationError) {
    console.error("Auth backend configuration invalid", {
      missing: error.missing,
      invalid: error.invalid,
    });
  } else {
    console.error("Auth backend configuration invalid");
  }
  process.exit(1);
}

const server = createServer(createApp(config, { verifyIdToken: createFirebaseIdTokenVerifier(config) }));
server.requestTimeout = 30_000;
server.headersTimeout = 35_000;
server.keepAliveTimeout = 5_000;
server.listen(config.port, "0.0.0.0", () => {
  console.info("auth_backend_started", { port: config.port, nodeEnv: config.nodeEnv });
});

let closing = false;
function shutdown(signal: string) {
  if (closing) return;
  closing = true;
  console.info("auth_backend_shutdown", { signal });
  server.close((error) => {
    if (error) {
      console.error("auth_backend_shutdown_failed", { errorName: error.name });
      process.exitCode = 1;
    }
  });
  const forceExit = setTimeout(() => process.exit(1), 10_000);
  forceExit.unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      globals: true,
      setupFiles: ["./tests/setup.ts"],
      include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
      // Grade D's crypto (RSA-1024 keygen via node-forge) is fast, but tests
      // that call generateKeyPair() several times still benefit from a little
      // more than vitest's 5s default.
      testTimeout: 20000,
    },
  }),
);

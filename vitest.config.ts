import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true, // Allows using describe, it, expect, etc. without importing
    environment: 'miniflare', // Or 'node' if not testing worker-specific features heavily
    // Optional: configuration for miniflare environment if needed
    // environmentOptions: {
    //   scriptPath: './dist/index.js', // if you want to test the built worker
    // },
    coverage: {
      provider: 'v8', // or 'istanbul'
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: [
        'src/types/**/*.d.ts',
        'src/index.ts', // Usually, the entry point is tested via integration tests
        'src/utils/mailauth-patch.ts' // Patching globals can be tricky to unit test
      ],
    },
  },
});

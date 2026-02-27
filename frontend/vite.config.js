import { defineConfig } from 'vite';

export default defineConfig({
  // Required for Barretenberg WASM + SharedArrayBuffer
  server: {
    host: '127.0.0.1',
    port: 5173,
    headers: {
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy':   'same-origin',
    },
  },
  preview: {
    headers: {
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy':   'same-origin',
    },
  },

  // Let Vite pre-bundle these so esbuild converts @aztec/bb.js (a webpack CJS
  // bundle) to proper ESM — without this the browser throws "exports is not
  // defined" and the entire module graph fails to load.
  optimizeDeps: {
    include: [
      '@noir-lang/backend_barretenberg',
      '@noir-lang/noir_js',
    ],
    esbuildOptions: {
      target: 'esnext',  // @aztec/bb.js uses top-level await
    },
  },

  build: {
    target: 'esnext',
    rollupOptions: {
      output: {
        manualChunks: {
          'noir': ['@noir-lang/noir_js', '@noir-lang/backend_barretenberg'],
        },
      },
    },
  },

  // Allow importing JSON files (circuit artifact)
  json: { stringify: false },
});

import { defineConfig } from 'vite';

export default defineConfig({
  // Required for Barretenberg WASM + SharedArrayBuffer
  server: {
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

  // Vite must not pre-bundle WASM packages — they ship their own loader
  optimizeDeps: {
    exclude: [
      '@noir-lang/backend_barretenberg',
      '@noir-lang/noir_js',
      '@noir-lang/acvm_js',
      '@noir-lang/noirc_abi',
      '@noir-lang/types',
    ],
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

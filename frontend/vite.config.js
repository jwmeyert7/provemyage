import { defineConfig } from 'vite';
import basicSsl from '@vitejs/plugin-basic-ssl';

export default defineConfig({
  plugins: [basicSsl()],

  // Required for Barretenberg WASM + SharedArrayBuffer
  server: {
    host: true,   // bind to all interfaces (0.0.0.0) so phone can reach it
    port: 5173,
    https: true,
    headers: {
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy':   'same-origin',
    },
    // Proxy /api/* to the backend - phone uses same-origin HTTPS, no CORS needed
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        rewrite: path => path.replace(/^\/api/, ''),
        changeOrigin: true,
      },
    },
  },
  preview: {
    headers: {
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy':   'same-origin',
    },
  },

  // Let Vite pre-bundle these so esbuild converts @aztec/bb.js (a webpack CJS
  // bundle) to proper ESM - without this the browser throws "exports is not
  // defined" and the entire module graph fails to load.
  optimizeDeps: {
    // Pre-bundle the high-level packages (converts @aztec/bb.js CJS→ESM)
    include: [
      '@noir-lang/backend_barretenberg',
      '@noir-lang/noir_js',
    ],
    // Keep these excluded so they run from their real node_modules path.
    // They use `new URL('./foo.wasm', import.meta.url)` to load WASM, which
    // only resolves correctly when the file is served from its own directory.
    // Inlining them into a pre-bundled dep moves import.meta.url to
    // .vite/deps/ and the WASM fetch returns a 404 HTML page.
    exclude: [
      '@noir-lang/acvm_js',
      '@noir-lang/noirc_abi',
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

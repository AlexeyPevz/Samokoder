import path from "path"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  css: {
    postcss: {
      plugins: [
        tailwindcss,
        autoprefixer,
      ],
    },
  },
  build: {
    // Optimize chunk splitting for better caching and loading
    rollupOptions: {
      output: {
        manualChunks: {
          // Vendor chunk for React and core libraries
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          // UI libraries chunk
          'vendor-ui': [
            '@radix-ui/react-dialog',
            '@radix-ui/react-dropdown-menu',
            '@radix-ui/react-tabs',
            '@radix-ui/react-toast',
            '@radix-ui/react-tooltip',
            '@radix-ui/react-select',
            '@radix-ui/react-scroll-area',
          ],
          // Monaco editor - large dependency
          'vendor-monaco': ['@monaco-editor/react'],
          // Charts and visualization
          'vendor-charts': ['recharts'],
          // Form libraries
          'vendor-forms': ['react-hook-form', 'zod'],
          // Utilities
          'vendor-utils': [
            'axios',
            'date-fns',
            'clsx',
            'class-variance-authority',
            'tailwind-merge',
          ],
        },
      },
    },
    // Increase chunk size warning limit to 600KB (we've split into chunks)
    chunkSizeWarningLimit: 600,
    // Enable CSS code splitting
    cssCodeSplit: true,
    // Optimize source maps for production (smaller, faster)
    sourcemap: false,
    // Minify with esbuild for faster builds and good compression
    minify: 'esbuild',
    // Target modern browsers for smaller bundles
    target: 'es2020',
    // Additional esbuild options
    esbuild: {
      drop: ['console', 'debugger'], // Remove console and debugger in production
      legalComments: 'none', // Remove comments
    },
  },
  // Enable dependency optimization
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
    ],
  },
  server: {
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      }
    },
    hmr: {
      clientPort: 443,
    },
    watch: {
      ignored: ['**/node_modules/**', '**/.git/**'],
    }
  }
})

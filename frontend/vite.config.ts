import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // Оптимизация сборки для производительности
    target: 'esnext',
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info', 'console.debug'],
        passes: 2,
      },
      mangle: {
        safari10: true,
      },
    },
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // Более агрессивное разделение чанков для лучшего кеширования
          if (id.includes('node_modules')) {
            // React ecosystem
            if (id.includes('react') || id.includes('react-dom')) {
              return 'react-vendor';
            }
            // Router
            if (id.includes('react-router')) {
              return 'router-vendor';
            }
            // UI libraries
            if (id.includes('@radix-ui') || id.includes('lucide-react') || id.includes('@heroicons')) {
              return 'ui-vendor';
            }
            // Utils and state management
            if (id.includes('axios') || id.includes('zod') || id.includes('zustand') || id.includes('clsx') || id.includes('tailwind-merge')) {
              return 'utils-vendor';
            }
            // Charts and visualization
            if (id.includes('recharts') || id.includes('framer-motion')) {
              return 'charts-vendor';
            }
            // Forms and validation
            if (id.includes('react-hook-form') || id.includes('@hookform')) {
              return 'forms-vendor';
            }
            // Date utilities
            if (id.includes('date-fns')) {
              return 'date-vendor';
            }
            // Other vendor libraries
            return 'vendor';
          }
          // App chunks based on routes
          if (id.includes('/pages/Home') || id.includes('/components/home/')) {
            return 'home';
          }
          if (id.includes('/pages/Dashboard') || id.includes('/components/dashboard/')) {
            return 'dashboard';
          }
          if (id.includes('/pages/Workspace') || id.includes('/components/workspace/')) {
            return 'workspace';
          }
          if (id.includes('/pages/Settings')) {
            return 'settings';
          }
          if (id.includes('/pages/Login') || id.includes('/pages/Register')) {
            return 'auth';
          }
        },
        // Оптимизация имен файлов для кеширования
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: (assetInfo) => {
          const info = assetInfo.name.split('.');
          const ext = info[info.length - 1];
          if (/\.(css)$/.test(assetInfo.name)) {
            return `assets/[name]-[hash].${ext}`;
          }
          return `assets/[name]-[hash].${ext}`;
        },
      },
    },
    // Включение source maps только для development
    sourcemap: process.env.NODE_ENV === 'development',
    // Оптимизация размера чанков
    chunkSizeWarningLimit: 500,
    // Включение CSS code splitting
    cssCodeSplit: true,
  },
  server: {
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/logs': {
        target: 'http://localhost:4444',
        changeOrigin: true,
      }
    },
    allowedHosts: [
      'localhost',
      '.pythagora.ai'
    ],
    watch: {
      ignored: ['**/node_modules/**', '**/dist/**', '**/public/**', '**/log/**']
    }
  },
  // Оптимизация зависимостей
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'axios',
      'zustand'
    ],
    exclude: ['@vite/client', '@vite/env']
  },
  // Настройки для улучшения производительности
  esbuild: {
    target: 'esnext',
    minifyIdentifiers: true,
    minifySyntax: true,
    minifyWhitespace: true,
  },
})

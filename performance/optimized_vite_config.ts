/**
 * Оптимизированная конфигурация Vite для улучшения Core Web Vitals
 */

import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { visualizer } from 'rollup-plugin-visualizer'

export default defineConfig({
  plugins: [
    react({
      // Оптимизация React для production
      babel: {
        plugins: [
          // Удаление console.log в production
          process.env.NODE_ENV === 'production' && [
            'transform-remove-console',
            { exclude: ['error', 'warn'] }
          ]
        ].filter(Boolean)
      }
    }),
    // Анализ bundle размера
    visualizer({
      filename: 'dist/stats.html',
      open: true,
      gzipSize: true,
      brotliSize: true
    })
  ],
  
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  
  // Оптимизация сборки
  build: {
    target: 'esnext',
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info']
      }
    },
    
    // Code splitting
    rollupOptions: {
      output: {
        manualChunks: {
          // Vendor chunks
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu', '@radix-ui/react-tooltip'],
          'animation-vendor': ['framer-motion'],
          'utils-vendor': ['date-fns', 'clsx', 'tailwind-merge'],
          'query-vendor': ['react-query'],
          'form-vendor': ['react-hook-form', '@hookform/resolvers', 'zod']
        },
        
        // Оптимизация имен файлов
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    },
    
    // Увеличение лимита для предупреждений
    chunkSizeWarningLimit: 1000,
    
    // Оптимизация CSS
    cssCodeSplit: true,
    cssMinify: true
  },
  
  // Оптимизация dev сервера
  server: {
    host: true,
    port: 5173,
    
    // HTTP/2 для лучшей производительности
    https: false,
    
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        secure: false
      },
      '/logs': {
        target: 'http://localhost:4444',
        changeOrigin: true,
        secure: false
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
  
  // Оптимизация preview сервера
  preview: {
    port: 4173,
    host: true,
    cors: true
  },
  
  // Оптимизация зависимостей
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'framer-motion',
      'date-fns',
      'clsx',
      'tailwind-merge'
    ],
    exclude: [
      // Исключаем тяжелые зависимости из pre-bundling
    ]
  },
  
  // Настройки для PWA (если нужно)
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    __BUILD_TIME__: JSON.stringify(new Date().toISOString())
  }
})
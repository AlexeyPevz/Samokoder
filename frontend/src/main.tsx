
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { preloadCriticalResources, optimizeImages } from './utils/performance'
import { logWebVitals } from './reportWebVitals'

// Initialize performance optimizations
preloadCriticalResources();

// Start Web Vitals measurement (only in development/staging)
if (import.meta.env.DEV || window.location.hostname !== 'production.example.com') {
  logWebVitals();
}

// Optimize images after DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  optimizeImages();
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)


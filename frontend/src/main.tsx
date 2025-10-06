
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { preloadCriticalResources, optimizeImages } from './utils/performance'

// Initialize performance optimizations
preloadCriticalResources();

// Register Service Worker for caching and performance
// Register Service Worker for caching and performance
// if ('serviceWorker' in navigator) {
//   window.addEventListener('load', () => {
//     navigator.serviceWorker.register('/sw.js')
//       .then((registration) => {
//       })
//       .catch((registrationError) => {
//       });
//   });
// }

// Optimize images after DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  optimizeImages();
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)


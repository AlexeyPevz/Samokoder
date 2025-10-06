// Performance monitoring utilities for Core Web Vitals
export interface WebVitals {
  lcp: number | null; // Largest Contentful Paint (target: ≤ 2.5s)
  inp: number | null; // Interaction to Next Paint (target: ≤ 200ms)
  cls: number | null; // Cumulative Layout Shift (target: ≤ 0.1)
  fcp: number | null; // First Contentful Paint
  fid: number | null; // First Input Delay
  ttfb: number | null; // Time to First Byte
}

export class PerformanceMonitor {
  private vitals: WebVitals = {
    lcp: null,
    inp: null,
    cls: null,
    fcp: null,
    fid: null,
    ttfb: null
  };

  private observers: PerformanceObserver[] = [];

  constructor() {
    this.initializeObservers();
  }

  private initializeObservers() {
    // LCP Observer
    if ('PerformanceObserver' in window) {
      try {
        const lcpObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const lastEntry = entries[entries.length - 1] as PerformanceEventTiming;
          this.vitals.lcp = lastEntry.startTime;
        });
        lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] });
        this.observers.push(lcpObserver);
      } catch (e) {
        console.warn('LCP observer not supported');
      }

      // CLS Observer
      try {
        let clsValue = 0;
        const clsObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (!(entry as any).hadRecentInput) {
              clsValue += (entry as any).value;
            }
          }
          this.vitals.cls = clsValue;
        });
        clsObserver.observe({ entryTypes: ['layout-shift'] });
        this.observers.push(clsObserver);
      } catch (e) {
        console.warn('CLS observer not supported');
      }

      // FCP Observer
      try {
        const fcpObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const fcpEntry = entries.find(entry => entry.name === 'first-contentful-paint');
          if (fcpEntry) {
            this.vitals.fcp = fcpEntry.startTime;
          }
        });
        fcpObserver.observe({ entryTypes: ['paint'] });
        this.observers.push(fcpObserver);
      } catch (e) {
        console.warn('FCP observer not supported');
      }

      // FID Observer
      try {
        const fidObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          for (const entry of entries) {
            if (entry.entryType === 'first-input') {
              this.vitals.fid = (entry as any).processingStart - entry.startTime;
            }
          }
        });
        fidObserver.observe({ entryTypes: ['first-input'] });
        this.observers.push(fidObserver);
      } catch (e) {
        console.warn('FID observer not supported');
      }

      // TTFB Observer
      try {
        const ttfbObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const navigationEntry = entries.find(entry => entry.entryType === 'navigation');
          if (navigationEntry) {
            this.vitals.ttfb = (navigationEntry as any).responseStart - (navigationEntry as any).requestStart;
          }
        });
        ttfbObserver.observe({ entryTypes: ['navigation'] });
        this.observers.push(ttfbObserver);
      } catch (e) {
        console.warn('TTFB observer not supported');
      }
    }

    // INP measurement (simplified)
    this.measureINP();
  }

  private measureINP() {
    let maxDelay = 0;
    const measureInteraction = (event: Event) => {
      const start = performance.now();
      requestAnimationFrame(() => {
        const delay = performance.now() - start;
        maxDelay = Math.max(maxDelay, delay);
        this.vitals.inp = maxDelay;
      });
    };

    ['click', 'keydown', 'touchstart'].forEach(eventType => {
      document.addEventListener(eventType, measureInteraction, { passive: true });
    });
  }

  public getVitals(): WebVitals {
    return { ...this.vitals };
  }

  public getVitalsReport(): string {
    const vitals = this.getVitals();
    const report = `
Core Web Vitals Report:
=======================
LCP (Largest Contentful Paint): ${vitals.lcp ? `${vitals.lcp.toFixed(2)}ms` : 'N/A'} ${vitals.lcp && vitals.lcp <= 2500 ? '✅' : '❌'} (Target: ≤ 2.5s)
INP (Interaction to Next Paint): ${vitals.inp ? `${vitals.inp.toFixed(2)}ms` : 'N/A'} ${vitals.inp && vitals.inp <= 200 ? '✅' : '❌'} (Target: ≤ 200ms)
CLS (Cumulative Layout Shift): ${vitals.cls ? vitals.cls.toFixed(3) : 'N/A'} ${vitals.cls && vitals.cls <= 0.1 ? '✅' : '❌'} (Target: ≤ 0.1)
FCP (First Contentful Paint): ${vitals.fcp ? `${vitals.fcp.toFixed(2)}ms` : 'N/A'}
FID (First Input Delay): ${vitals.fid ? `${vitals.fid.toFixed(2)}ms` : 'N/A'}
TTFB (Time to First Byte): ${vitals.ttfb ? `${vitals.ttfb.toFixed(2)}ms` : 'N/A'}
    `;
    return report;
  }

  public disconnect() {
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
  }
}

// Bundle analyzer utility
export const analyzeBundleSize = () => {
  if (typeof window !== 'undefined' && 'performance' in window) {
    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
    const jsResources = resources.filter(resource => 
      resource.name.includes('.js') && !resource.name.includes('node_modules')
    );
    
    const totalJSSize = jsResources.reduce((total, resource) => {
      return total + (resource.transferSize || 0);
    }, 0);

    
    return {
      jsResources: jsResources.length,
      totalJSSize: totalJSSize,
      totalJSSizeKB: Math.round(totalJSSize / 1024)
    };
  }
  return null;
};

// Performance optimization utilities
export const preloadCriticalResources = () => {
  // Preload API endpoint for faster initial data fetch
  if ('dns-prefetch' in document.createElement('link')) {
    const apiPrefetch = document.createElement('link');
    apiPrefetch.rel = 'dns-prefetch';
    apiPrefetch.href = window.location.origin;
    document.head.appendChild(apiPrefetch);
  }
  
  // Preconnect to API for faster requests
  const apiPreconnect = document.createElement('link');
  apiPreconnect.rel = 'preconnect';
  apiPreconnect.href = window.location.origin;
  document.head.appendChild(apiPreconnect);
};

export const optimizeImages = () => {
  // Add loading="lazy" to all images except first 2 (LCP optimization)
  const images = document.querySelectorAll('img');
  images.forEach((img, index) => {
    // First 2 images are likely above the fold - load eagerly
    if (index >= 2) {
      if (!img.hasAttribute('loading')) {
        img.setAttribute('loading', 'lazy');
      }
    }
    if (!img.hasAttribute('decoding')) {
      img.setAttribute('decoding', 'async');
    }
    // Add fetchpriority="high" to LCP candidate (first image)
    if (index === 0 && !img.hasAttribute('fetchpriority')) {
      img.setAttribute('fetchpriority', 'high');
    }
  });
  
  // Observe images for lazy loading analytics
  if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target as HTMLImageElement;
          // Image is now visible
          imageObserver.unobserve(img);
        }
      });
    });
    
    images.forEach(img => imageObserver.observe(img));
  }
};

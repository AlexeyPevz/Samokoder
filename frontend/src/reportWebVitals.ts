// Web Vitals reporting utility
// This file integrates with the web-vitals library to measure Core Web Vitals

import { onCLS, onINP, onLCP, onFCP, onTTFB } from 'web-vitals';

export interface VitalsMetric {
  name: string;
  value: number;
  rating: 'good' | 'needs-improvement' | 'poor';
  delta: number;
  id: string;
}

// Thresholds based on Google's Core Web Vitals recommendations
const THRESHOLDS = {
  LCP: { good: 2500, poor: 4000 },
  INP: { good: 200, poor: 500 },
  CLS: { good: 0.1, poor: 0.25 },
  FCP: { good: 1800, poor: 3000 },
  FID: { good: 100, poor: 300 },
  TTFB: { good: 800, poor: 1800 },
};

function getRating(name: string, value: number): 'good' | 'needs-improvement' | 'poor' {
  const threshold = THRESHOLDS[name as keyof typeof THRESHOLDS];
  if (!threshold) return 'good';
  
  if (value <= threshold.good) return 'good';
  if (value <= threshold.poor) return 'needs-improvement';
  return 'poor';
}

export function reportWebVitals(onPerfEntry?: (metric: VitalsMetric) => void) {
  if (onPerfEntry && typeof onPerfEntry === 'function') {
    onCLS((metric: any) => {
      const vitalsMetric: VitalsMetric = {
        name: 'CLS',
        value: metric.value,
        rating: getRating('CLS', metric.value),
        delta: metric.delta,
        id: metric.id,
      };
      onPerfEntry(vitalsMetric);
    });
    
    onINP((metric: any) => {
      const vitalsMetric: VitalsMetric = {
        name: 'INP',
        value: metric.value,
        rating: getRating('INP', metric.value),
        delta: metric.delta,
        id: metric.id,
      };
      onPerfEntry(vitalsMetric);
    });
    
    onLCP((metric: any) => {
      const vitalsMetric: VitalsMetric = {
        name: 'LCP',
        value: metric.value,
        rating: getRating('LCP', metric.value),
        delta: metric.delta,
        id: metric.id,
      };
      onPerfEntry(vitalsMetric);
    });
    
    onFCP((metric: any) => {
      const vitalsMetric: VitalsMetric = {
        name: 'FCP',
        value: metric.value,
        rating: getRating('FCP', metric.value),
        delta: metric.delta,
        id: metric.id,
      };
      onPerfEntry(vitalsMetric);
    });
    
    onTTFB((metric: any) => {
      const vitalsMetric: VitalsMetric = {
        name: 'TTFB',
        value: metric.value,
        rating: getRating('TTFB', metric.value),
        delta: metric.delta,
        id: metric.id,
      };
      onPerfEntry(vitalsMetric);
    });
  }
}

// Console logger for development
export function logWebVitals() {
  const vitalsLog: Record<string, VitalsMetric> = {};
  
  reportWebVitals((metric) => {
    vitalsLog[metric.name] = metric;
    
    const emoji = metric.rating === 'good' ? '✅' : metric.rating === 'needs-improvement' ? '⚠️' : '❌';
    const value = metric.name === 'CLS' ? metric.value.toFixed(3) : `${metric.value.toFixed(0)}ms`;
    
    console.log(`${emoji} ${metric.name}: ${value} (${metric.rating})`);
  });
  
  // Log summary after page load
  window.addEventListener('load', () => {
    setTimeout(() => {
      console.log('=== Core Web Vitals Summary ===');
      console.table(vitalsLog);
      
      // Make available globally for debugging
      (window as any).__webVitals = vitalsLog;
    }, 3000);
  });
}

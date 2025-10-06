import { useEffect, useRef, useCallback, useMemo, useState } from 'react';
import { PerformanceMonitor, analyzeBundleSize } from '../utils/performance';

// Hook for performance monitoring
export const usePerformance = () => {
  const monitorRef = useRef<PerformanceMonitor | null>(null);

  useEffect(() => {
    // Initialize performance monitor
    monitorRef.current = new PerformanceMonitor();

    // Analyze bundle size
    const bundleAnalysis = analyzeBundleSize();
    if (bundleAnalysis) {
    }

    // Cleanup on unmount
    return () => {
      if (monitorRef.current) {
        monitorRef.current.disconnect();
      }
    };
  }, []);

  const getVitals = useCallback(() => {
    return monitorRef.current?.getVitals() || null;
  }, []);

  const getVitalsReport = useCallback(() => {
    return monitorRef.current?.getVitalsReport() || 'Performance monitor not initialized';
  }, []);

  return {
    getVitals,
    getVitalsReport
  };
};

// Hook for debounced values
export const useDebounce = <T>(value: T, delay: number): T => {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
};

// Hook for throttled callbacks
export const useThrottle = <T extends (...args: any[]) => any>(
  callback: T,
  delay: number
): T => {
  const lastRun = useRef(Date.now());

  return useCallback((...args: Parameters<T>) => {
    if (Date.now() - lastRun.current >= delay) {
      callback(...args);
      lastRun.current = Date.now();
    }
  }, [callback, delay]) as T;
};

// Hook for intersection observer (lazy loading)
export const useIntersectionObserver = (
  callback: IntersectionObserverCallback,
  options?: IntersectionObserverInit
) => {
  const observerRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined' && 'IntersectionObserver' in window) {
      observerRef.current = new IntersectionObserver(callback, options);
    }

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, [callback, options]);

  const observe = useCallback((element: Element) => {
    if (observerRef.current) {
      observerRef.current.observe(element);
    }
  }, []);

  const unobserve = useCallback((element: Element) => {
    if (observerRef.current) {
      observerRef.current.unobserve(element);
    }
  }, []);

  return { observe, unobserve };
};

// Hook for virtual scrolling
export const useVirtualScroll = (
  itemCount: number,
  itemHeight: number,
  containerHeight: number
) => {
  const [scrollTop, setScrollTop] = useState(0);

  const visibleRange = useMemo(() => {
    const startIndex = Math.floor(scrollTop / itemHeight);
    const endIndex = Math.min(
      startIndex + Math.ceil(containerHeight / itemHeight) + 1,
      itemCount
    );
    return { startIndex, endIndex };
  }, [scrollTop, itemHeight, containerHeight, itemCount]);

  const totalHeight = itemCount * itemHeight;
  const offsetY = visibleRange.startIndex * itemHeight;

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, []);

  return {
    visibleRange,
    totalHeight,
    offsetY,
    handleScroll
  };
};

// Hook for performance optimization
export const usePerformanceOptimization = () => {
  const [isVisible, setIsVisible] = useState(false);
  const elementRef = useRef<HTMLElement>(null);

  const { observe, unobserve } = useIntersectionObserver(
    useCallback((entries) => {
      const [entry] = entries;
      setIsVisible(entry.isIntersecting);
    }, []),
    { threshold: 0.1 }
  );

  useEffect(() => {
    const element = elementRef.current;
    if (element) {
      observe(element);
    }

    return () => {
      if (element) {
        unobserve(element);
      }
    };
  }, [observe, unobserve]);

  return {
    elementRef,
    isVisible
  };
};

// Hook for memory optimization
export const useMemoryOptimization = () => {
  const cleanupFunctions = useRef<(() => void)[]>([]);

  const addCleanup = useCallback((cleanup: () => void) => {
    cleanupFunctions.current.push(cleanup);
  }, []);

  useEffect(() => {
    return () => {
      // Run all cleanup functions
      cleanupFunctions.current.forEach(cleanup => cleanup());
      cleanupFunctions.current = [];
    };
  }, []);

  return { addCleanup };
};
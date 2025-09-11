import React, { Suspense, lazy, ComponentType, ErrorBoundary } from 'react';
import { Loader2, AlertCircle } from 'lucide-react';

// Optimized loading component with skeleton
const LoadingSpinner = () => (
  <div className="flex flex-col items-center justify-center min-h-[200px] space-y-4">
    <div className="relative">
      <Loader2 className="h-8 w-8 animate-spin text-samokoder-blue" />
      <div className="absolute inset-0 rounded-full border-2 border-samokoder-blue/20"></div>
    </div>
    <div className="text-center">
      <p className="text-sm text-muted-foreground">Загрузка...</p>
      <div className="mt-2 w-32 h-1 bg-gray-200 rounded-full overflow-hidden">
        <div className="h-full bg-samokoder-blue rounded-full animate-pulse"></div>
      </div>
    </div>
  </div>
);

// Skeleton loading for better perceived performance
const SkeletonLoader = () => (
  <div className="animate-pulse space-y-4">
    <div className="h-8 bg-gray-200 rounded w-3/4"></div>
    <div className="space-y-2">
      <div className="h-4 bg-gray-200 rounded w-full"></div>
      <div className="h-4 bg-gray-200 rounded w-5/6"></div>
      <div className="h-4 bg-gray-200 rounded w-4/6"></div>
    </div>
    <div className="h-32 bg-gray-200 rounded"></div>
  </div>
);

// Error boundary component
class LazyErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error?: Error }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Lazy loading error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[200px] space-y-4 p-6">
          <AlertCircle className="h-12 w-12 text-red-500" />
          <div className="text-center">
            <h3 className="text-lg font-semibold text-gray-900">Ошибка загрузки</h3>
            <p className="text-sm text-gray-600 mt-2">
              Не удалось загрузить компонент. Попробуйте обновить страницу.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="mt-4 px-4 py-2 bg-samokoder-blue text-white rounded-md hover:bg-samokoder-blue-dark transition-colors"
            >
              Обновить страницу
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// HOC for lazy loading with error boundary
export const withLazyLoading = <P extends object>(
  Component: ComponentType<P>,
  fallback?: React.ComponentType
) => {
  const LazyComponent = lazy(() => Promise.resolve({ default: Component }));
  
  return (props: P) => (
    <LazyErrorBoundary>
      <Suspense fallback={fallback ? <fallback /> : <SkeletonLoader />}>
        <LazyComponent {...props} />
      </Suspense>
    </LazyErrorBoundary>
  );
};

// Generic lazy wrapper component with error boundary
interface LazyWrapperProps {
  children: React.ReactNode;
  fallback?: React.ComponentType;
  useSkeleton?: boolean;
}

export const LazyWrapper: React.FC<LazyWrapperProps> = ({ 
  children, 
  fallback,
  useSkeleton = false
}) => (
  <LazyErrorBoundary>
    <Suspense fallback={fallback ? <fallback /> : (useSkeleton ? <SkeletonLoader /> : <LoadingSpinner />)}>
      {children}
    </Suspense>
  </LazyErrorBoundary>
);

// Preload function for critical components
export const preloadComponent = (importFn: () => Promise<any>) => {
  const link = document.createElement('link');
  link.rel = 'modulepreload';
  link.href = importFn().then(module => module.default);
  document.head.appendChild(link);
};

export default LazyWrapper;
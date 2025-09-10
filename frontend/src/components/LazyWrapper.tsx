import React, { Suspense, lazy, ComponentType } from 'react';
import { Loader2 } from 'lucide-react';

// Loading component for better UX
const LoadingSpinner = () => (
  <div className="flex items-center justify-center min-h-[200px]">
    <Loader2 className="h-8 w-8 animate-spin" />
    <span className="ml-2 text-sm text-muted-foreground">Loading...</span>
  </div>
);

// HOC for lazy loading with error boundary
export const withLazyLoading = <P extends object>(
  Component: ComponentType<P>,
  fallback?: React.ComponentType
) => {
  const LazyComponent = lazy(() => Promise.resolve({ default: Component }));
  
  return (props: P) => (
    <Suspense fallback={fallback ? <fallback /> : <LoadingSpinner />}>
      <LazyComponent {...props} />
    </Suspense>
  );
};

// Generic lazy wrapper component
interface LazyWrapperProps {
  children: React.ReactNode;
  fallback?: React.ComponentType;
}

export const LazyWrapper: React.FC<LazyWrapperProps> = ({ 
  children, 
  fallback 
}) => (
  <Suspense fallback={fallback ? <fallback /> : <LoadingSpinner />}>
    {children}
  </Suspense>
);

export default LazyWrapper;
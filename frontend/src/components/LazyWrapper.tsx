import React, { Suspense, ComponentType } from 'react';
import { Loader2, AlertCircle } from 'lucide-react';

// A simple loading spinner
const LoadingSpinner = () => (
  <div className="flex items-center justify-center min-h-[200px]">
    <Loader2 className="h-8 w-8 animate-spin text-samokoder-blue" />
  </div>
);

// Error boundary component specific to lazy loading
class LazyErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Lazy loading error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[200px] p-6">
          <AlertCircle className="h-12 w-12 text-red-500" />
          <h3 className="mt-4 text-lg font-semibold">Ошибка загрузки</h3>
          <p className="mt-2 text-sm text-gray-600">Не удалось загрузить компонент.</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 px-4 py-2 bg-samokoder-blue text-white rounded-md hover:bg-samokoder-blue-dark"
          >
            Обновить
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

// Simplified generic lazy wrapper
interface LazyWrapperProps {
  children: React.ReactNode;
}

const LazyWrapper: React.FC<LazyWrapperProps> = ({ children }) => (
  <LazyErrorBoundary>
    <Suspense fallback={<LoadingSpinner />}>
      {children}
    </Suspense>
  </LazyErrorBoundary>
);

export default LazyWrapper;
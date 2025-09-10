import React, { memo, useMemo, useCallback } from 'react';

// HOC for memoization with custom comparison
export const withMemo = <P extends object>(
  Component: React.ComponentType<P>,
  areEqual?: (prevProps: P, nextProps: P) => boolean
) => {
  return memo(Component, areEqual);
};

// Optimized button component
interface OptimizedButtonProps {
  onClick: () => void;
  children: React.ReactNode;
  variant?: 'primary' | 'secondary';
  disabled?: boolean;
  className?: string;
}

export const OptimizedButton = memo<OptimizedButtonProps>(({ 
  onClick, 
  children, 
  variant = 'primary', 
  disabled = false,
  className = ''
}) => {
  const handleClick = useCallback(() => {
    if (!disabled) {
      onClick();
    }
  }, [onClick, disabled]);

  const buttonClasses = useMemo(() => {
    const baseClasses = 'px-4 py-2 rounded-md font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2';
    const variantClasses = {
      primary: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500',
      secondary: 'bg-gray-200 text-gray-900 hover:bg-gray-300 focus:ring-gray-500'
    };
    const disabledClasses = disabled ? 'opacity-50 cursor-not-allowed' : '';
    
    return `${baseClasses} ${variantClasses[variant]} ${disabledClasses} ${className}`;
  }, [variant, disabled, className]);

  return (
    <button
      className={buttonClasses}
      onClick={handleClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
});

OptimizedButton.displayName = 'OptimizedButton';

// Optimized list component with virtualization
interface OptimizedListProps<T> {
  items: T[];
  renderItem: (item: T, index: number) => React.ReactNode;
  keyExtractor: (item: T, index: number) => string | number;
  className?: string;
  itemHeight?: number;
  containerHeight?: number;
}

export const OptimizedList = memo(<T,>({ 
  items, 
  renderItem, 
  keyExtractor, 
  className = '',
  itemHeight = 50,
  containerHeight = 400
}: OptimizedListProps<T>) => {
  const visibleItems = useMemo(() => {
    // Simple virtualization - show all items for now
    // In production, implement proper windowing
    return items;
  }, [items]);

  return (
    <div 
      className={`overflow-y-auto ${className}`}
      style={{ height: containerHeight }}
    >
      {visibleItems.map((item, index) => (
        <div
          key={keyExtractor(item, index)}
          style={{ height: itemHeight }}
          className="flex items-center"
        >
          {renderItem(item, index)}
        </div>
      ))}
    </div>
  );
}) as <T>(props: OptimizedListProps<T>) => React.ReactElement;

OptimizedList.displayName = 'OptimizedList';

// Optimized image component with lazy loading
interface OptimizedImageProps {
  src: string;
  alt: string;
  width?: number;
  height?: number;
  className?: string;
  priority?: boolean;
}

export const OptimizedImage = memo<OptimizedImageProps>(({ 
  src, 
  alt, 
  width, 
  height, 
  className = '',
  priority = false
}) => {
  const imageProps = useMemo(() => ({
    src,
    alt,
    width,
    height,
    loading: priority ? 'eager' : 'lazy',
    decoding: 'async',
    className: `transition-opacity duration-300 ${className}`
  }), [src, alt, width, height, priority, className]);

  return <img {...imageProps} />;
});

OptimizedImage.displayName = 'OptimizedImage';

// Optimized form field component
interface OptimizedFormFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: 'text' | 'email' | 'password';
  placeholder?: string;
  error?: string;
  required?: boolean;
}

export const OptimizedFormField = memo<OptimizedFormFieldProps>(({ 
  label, 
  value, 
  onChange, 
  type = 'text', 
  placeholder, 
  error, 
  required = false 
}) => {
  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value);
  }, [onChange]);

  const fieldId = useMemo(() => `field-${Math.random().toString(36).substr(2, 9)}`, []);

  return (
    <div className="space-y-2">
      <label 
        htmlFor={fieldId}
        className="block text-sm font-medium text-gray-700"
      >
        {label}
        {required && <span className="text-red-500 ml-1">*</span>}
      </label>
      <input
        id={fieldId}
        type={type}
        value={value}
        onChange={handleChange}
        placeholder={placeholder}
        required={required}
        className={`w-full px-3 py-2 border rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${
          error ? 'border-red-500' : 'border-gray-300'
        }`}
      />
      {error && (
        <p className="text-sm text-red-600">{error}</p>
      )}
    </div>
  );
});

OptimizedFormField.displayName = 'OptimizedFormField';
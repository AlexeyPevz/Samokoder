import React from 'react';
import { cn } from '../../lib/utils';

interface SamokoderBadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'secondary' | 'accent' | 'outline' | 'success' | 'warning' | 'error';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

const SamokoderBadge: React.FC<SamokoderBadgeProps> = ({
  variant = 'default',
  size = 'md',
  className,
  children,
  ...props
}) => {
  const baseClasses = 'inline-flex items-center rounded-full font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-samokoder-blue focus:ring-offset-2';
  
  const variantClasses = {
    default: 'bg-samokoder-blue text-white hover:bg-samokoder-blue-dark',
    secondary: 'bg-samokoder-green text-white hover:bg-samokoder-green-dark',
    accent: 'bg-accent text-accent-foreground hover:bg-accent/80',
    outline: 'border border-samokoder-blue text-samokoder-blue hover:bg-samokoder-blue hover:text-white',
    success: 'bg-green-100 text-green-800 hover:bg-green-200 dark:bg-green-900 dark:text-green-200',
    warning: 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200 dark:bg-yellow-900 dark:text-yellow-200',
    error: 'bg-red-100 text-red-800 hover:bg-red-200 dark:bg-red-900 dark:text-red-200'
  };

  const sizeClasses = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-2.5 py-0.5 text-sm',
    lg: 'px-3 py-1 text-base'
  };

  return (
    <div
      className={cn(
        baseClasses,
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

export default SamokoderBadge;
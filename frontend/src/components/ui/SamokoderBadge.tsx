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
  const baseClasses = 'inline-flex items-center rounded-full font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-[#0A2E50] focus:ring-offset-2';
  
  const variantClasses = {
    default: 'bg-[#0A2E50] text-white hover:bg-[#083247]',
    secondary: 'bg-[#00A868] text-white hover:bg-[#00946B]',
    accent: 'bg-[#00A868] text-white hover:bg-[#00946B]',
    outline: 'border border-[#0A2E50] text-[#0A2E50] hover:bg-[#0A2E50] hover:text-white',
    success: 'bg-[#10B981]/10 text-[#10B981] hover:bg-[#10B981]/20',
    warning: 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200',
    error: 'bg-[#EF4444]/10 text-[#EF4444] hover:bg-[#EF4444]/20'
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
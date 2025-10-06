import React from 'react';
import { cn } from '../../lib/utils';

interface SamokoderButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'accent' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

const SamokoderButton: React.FC<SamokoderButtonProps> = ({
  variant = 'primary',
  size = 'md',
  className,
  children,
  ...props
}) => {
  const baseClasses = 'inline-flex items-center justify-center rounded-lg font-semibold transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50';
  
  const variantClasses = {
    primary: 'bg-[#0A2E50] text-white hover:bg-[#083247] hover:transform hover:translate-y-[-1px] shadow-sm focus-visible:ring-[#0A2E50]',
    secondary: 'bg-transparent text-[#0A2E50] border-2 border-[#0A2E50] hover:bg-[#0A2E50] hover:text-white focus-visible:ring-[#0A2E50]',
    accent: 'bg-[#00A868] text-white hover:bg-[#00946B] hover:transform hover:translate-y-[-1px] shadow-sm focus-visible:ring-[#00A868]',
    outline: 'border-2 border-[#0A2E50] text-[#0A2E50] hover:bg-[#0A2E50] hover:text-white focus-visible:ring-[#0A2E50]',
    ghost: 'text-[#0A2E50] hover:bg-[#0A2E50]/10 focus-visible:ring-[#0A2E50]'
  };

  const sizeClasses = {
    sm: 'h-8 px-3 text-sm rounded-md',
    md: 'h-10 px-6 py-2 text-base',
    lg: 'h-12 px-8 text-lg'
  };

  return (
    <button
      className={cn(
        baseClasses,
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
};

export default SamokoderButton;
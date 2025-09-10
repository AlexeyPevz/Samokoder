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
  const baseClasses = 'inline-flex items-center justify-center rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue disabled:pointer-events-none disabled:opacity-50';
  
  const variantClasses = {
    primary: 'bg-samokoder-blue text-white hover:bg-samokoder-blue-dark shadow-sm',
    secondary: 'bg-samokoder-green text-white hover:bg-samokoder-green-dark shadow-sm',
    accent: 'bg-accent text-accent-foreground hover:bg-accent/90',
    outline: 'border border-samokoder-blue text-samokoder-blue hover:bg-samokoder-blue hover:text-white',
    ghost: 'text-samokoder-blue hover:bg-samokoder-blue/10'
  };

  const sizeClasses = {
    sm: 'h-8 px-3 text-sm',
    md: 'h-10 px-4 py-2',
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
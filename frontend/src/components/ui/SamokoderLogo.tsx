import React from 'react';
import { cn } from '../../lib/utils';

interface SamokoderLogoProps {
  variant?: 'default' | 'mono' | 'inverted' | 'outline' | 'text' | 'flat-solid' | 'negative-s' | 'frost-ice';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showText?: boolean;
  className?: string;
}

const SamokoderLogo: React.FC<SamokoderLogoProps> = ({
  variant = 'default',
  size = 'md',
  showText = true,
  className
}) => {
  const sizeClasses = {
    sm: 'w-6 h-6',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16'
  };

  const textSizeClasses = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-xl',
    xl: 'text-2xl'
  };

  const getLogoColors = () => {
    switch (variant) {
      case 'mono':
        return {
          brackets: 'text-samokoder-blue',
          lightning: 'text-samokoder-green'
        };
      case 'inverted':
        return {
          brackets: 'text-samokoder-green',
          lightning: 'text-white'
        };
      case 'outline':
        return {
          brackets: 'text-transparent stroke-samokoder-blue stroke-2',
          lightning: 'text-samokoder-green'
        };
      case 'negative-s':
        return {
          brackets: 'text-samokoder-blue',
          lightning: 'text-samokoder-green',
          s: 'text-white'
        };
      case 'frost-ice':
        return {
          brackets: 'text-samokoder-green',
          lightning: 'text-samokoder-green',
          s: 'text-white'
        };
      default:
        return {
          brackets: 'text-samokoder-blue',
          lightning: 'text-samokoder-green'
        };
    }
  };

  const colors = getLogoColors();

  const LogoIcon = () => (
    <div className={cn('relative flex items-center justify-center', sizeClasses[size])}>
      {/* Left bracket */}
      <svg
        className={cn('absolute left-0', colors.brackets)}
        viewBox="0 0 24 24"
        fill="currentColor"
      >
        <path d="M8 4C8 2.89543 8.89543 2 10 2H12C13.1046 2 14 2.89543 14 4V6C14 6.55228 13.5523 7 13 7H11C10.4477 7 10 6.55228 10 6V4H8Z" />
        <path d="M8 8C8 7.44772 8.44772 7 9 7H11C11.5523 7 12 7.44772 12 8V16C12 16.5523 11.5523 17 11 17H9C8.44772 17 8 16.5523 8 16V8Z" />
        <path d="M8 18C8 16.8954 8.89543 16 10 16H12C13.1046 16 14 16.8954 14 18V20C14 21.1046 13.1046 22 12 22H10C8.89543 22 8 21.1046 8 20V18Z" />
      </svg>

      {/* Right bracket */}
      <svg
        className={cn('absolute right-0', colors.brackets)}
        viewBox="0 0 24 24"
        fill="currentColor"
      >
        <path d="M16 4C16 2.89543 15.1046 2 14 2H12C10.8954 2 10 2.89543 10 4V6C10 6.55228 10.4477 7 11 7H13C13.5523 7 14 6.55228 14 6V4H16Z" />
        <path d="M16 8C16 7.44772 15.5523 7 15 7H13C12.4477 7 12 7.44772 12 8V16C12 16.5523 12.4477 17 13 17H15C15.5523 17 16 16.5523 16 16V8Z" />
        <path d="M16 18C16 16.8954 15.1046 16 14 16H12C10.8954 16 10 16.8954 10 18V20C10 21.1046 10.8954 22 12 22H14C15.1046 22 16 21.1046 16 20V18Z" />
      </svg>

      {/* Lightning bolt */}
      <svg
        className={cn('absolute z-10', colors.lightning)}
        viewBox="0 0 24 24"
        fill="currentColor"
      >
        <path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" />
      </svg>

      {/* Negative space 'S' for negative-s variant */}
      {variant === 'negative-s' && (
        <div className={cn('absolute z-5 flex items-center justify-center', colors.s)}>
          <span className="font-bold text-2xl">S</span>
        </div>
      )}
    </div>
  );

  if (!showText) {
    return <LogoIcon />;
  }

  return (
    <div className={cn('flex items-center space-x-2', className)}>
      <LogoIcon />
      <div className="flex flex-col">
        <span className={cn('font-bold text-samokoder-blue', textSizeClasses[size])}>
          SAMOKODER
        </span>
        <span className={cn('text-xs text-muted-foreground', size === 'sm' ? 'text-xs' : 'text-sm')}>
          AI Full-Stack Development Platform
        </span>
      </div>
    </div>
  );
};

export default SamokoderLogo;